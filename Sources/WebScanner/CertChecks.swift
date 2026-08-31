import Foundation
import Network
import Security

enum CertChecks {

    struct LeafInfo {
        var notAfter: Date?
        var notBefore: Date?
        var keyBits: Int?
        var isRSA: Bool
        var signatureOID: String?
        var subjectCN: String?
    }

    private static let weakSignatureOIDs: [String: String] = [
        "1.2.840.113549.1.1.2": "MD2 with RSA",
        "1.2.840.113549.1.1.3": "MD4 with RSA",
        "1.2.840.113549.1.1.4": "MD5 with RSA",
        "1.2.840.113549.1.1.5": "SHA-1 with RSA",
        "1.3.14.3.2.29":        "SHA-1 with RSA (OIW)",
        "1.2.840.10040.4.3":    "SHA-1 with DSA",
        "1.2.840.10045.4.1":    "SHA-1 with ECDSA",
    ]

    static func inspect(host: String, port: UInt16 = 443) async -> [Finding] {
        guard let der = await fetchLeafCertDER(host: host, port: port),
              let cert = SecCertificateCreateWithData(nil, der as CFData) else { return [] }
        return evaluate(parse(cert), host: host, port: port)
    }

    private static func fetchLeafCertDER(host: String, port: UInt16) async -> Data? {
        await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            guard let nwPort = NWEndpoint.Port(rawValue: port) else { cont.resume(returning: nil); return }
            let gate = ProbeGate()
            let queue = DispatchQueue(label: "cert-inspect")
            var captured: Data?

            let tls = NWProtocolTLS.Options()
            let sec = tls.securityProtocolOptions
            sec_protocol_options_set_tls_server_name(sec, host)
            sec_protocol_options_set_verify_block(sec, { _, trustRef, complete in
                let trust = sec_trust_copy_ref(trustRef).takeRetainedValue()
                if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                   let leaf = chain.first {
                    captured = SecCertificateCopyData(leaf) as Data
                }
                complete(true)
            }, queue)

            let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort,
                                    using: NWParameters(tls: tls))
            func finish(_ v: Data?) { gate.fire { conn.cancel(); cont.resume(returning: v) } }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:            finish(captured)
                case .failed:           finish(captured)
                case .waiting:          finish(nil)
                default:                break
                }
            }
            queue.asyncAfter(deadline: .now() + .milliseconds(5000)) { finish(captured) }
            conn.start(queue: queue)
        }
    }

    private static func parse(_ cert: SecCertificate) -> LeafInfo {
        var info = LeafInfo(notAfter: nil, notBefore: nil, keyBits: nil,
                            isRSA: false, signatureOID: nil, subjectCN: nil)

        let oids = [kSecOIDX509V1ValidityNotAfter,
                    kSecOIDX509V1ValidityNotBefore,
                    kSecOIDX509V1SignatureAlgorithm] as CFArray
        if let values = SecCertificateCopyValues(cert, oids, nil) as? [CFString: Any] {
            info.notAfter  = date(values, kSecOIDX509V1ValidityNotAfter)
            info.notBefore = date(values, kSecOIDX509V1ValidityNotBefore)
            info.signatureOID = signatureOID(values)
        }

        var cn: CFString?
        SecCertificateCopyCommonName(cert, &cn)
        info.subjectCN = cn as String?

        if let key = SecCertificateCopyKey(cert),
           let attrs = SecKeyCopyAttributes(key) as? [CFString: Any] {
            info.keyBits = attrs[kSecAttrKeySizeInBits] as? Int
            if let type = attrs[kSecAttrKeyType] as? String {
                info.isRSA = (type == (kSecAttrKeyTypeRSA as String))
            }
        }
        return info
    }

    private static func date(_ values: [CFString: Any], _ oid: CFString) -> Date? {
        guard let entry = values[oid] as? [CFString: Any],
              let num = entry[kSecPropertyKeyValue] as? NSNumber else { return nil }

        return Date(timeIntervalSinceReferenceDate: num.doubleValue)
    }

    private static func signatureOID(_ values: [CFString: Any]) -> String? {
        guard let entry = values[kSecOIDX509V1SignatureAlgorithm] as? [CFString: Any] else { return nil }
        if let nested = entry[kSecPropertyKeyValue] as? [[CFString: Any]] {
            for item in nested where (item[kSecPropertyKeyLabel] as? String) == "Algorithm" {
                if let oid = item[kSecPropertyKeyValue] as? String { return oid }
            }
        }
        return entry[kSecPropertyKeyValue] as? String
    }

    private static func evaluate(_ info: LeafInfo, host: String, port: UInt16) -> [Finding] {
        var out: [Finding] = []
        let loc = "https://\(host)" + (port == 443 ? "" : ":\(port)")
        let cn = info.subjectCN.map { " (CN=\($0))" } ?? ""

        if let notAfter = info.notAfter {
            let days = Int(notAfter.timeIntervalSinceNow / 86_400)
            if days < 0 {
                out.append(Finding(
                    title: "TLS certificate has expired",
                    severity: .high, category: "Transport Security", location: loc,
                    detail: "The server's leaf certificate\(cn) expired \(-days) day(s) ago (notAfter: \(fmt(notAfter))).",
                    evidence: "notAfter: \(fmt(notAfter)) - \(-days) day(s) in the past.",
                    exploit: "An expired certificate breaks the trust chain: browsers show a full-page warning that trains users to click through, and it signals unmaintained infrastructure an attacker can exploit for MITM once users are conditioned to ignore the warning.",
                    remediation: "Renew the certificate immediately and automate renewal (e.g. ACME / Let's Encrypt with auto-renew) so it never lapses again.",
                    reference: "CWE-298: Improper Validation of Certificate Expiration",
                    reproduction: "openssl s_client -connect \(host):\(port) -servername \(host) 2>/dev/null | openssl x509 -noout -enddate"))
            } else if days <= 21 {
                out.append(Finding(
                    title: "TLS certificate expiring soon (\(days) day\(days == 1 ? "" : "s"))",
                    severity: days <= 7 ? .medium : .low, category: "Transport Security", location: loc,
                    detail: "The server's leaf certificate\(cn) expires in \(days) day(s) (notAfter: \(fmt(notAfter))).",
                    evidence: "notAfter: \(fmt(notAfter)) - \(days) day(s) remaining.",
                    exploit: "If the certificate lapses before renewal, every client is met with a hard TLS error and the site becomes unreachable over HTTPS - an availability outage, and a window where users are pushed to ignore certificate warnings.",
                    remediation: "Renew now and put automated renewal + expiry monitoring in place so certificates rotate well before the deadline.",
                    reference: "CWE-298: Improper Validation of Certificate Expiration",
                    reproduction: "openssl s_client -connect \(host):\(port) -servername \(host) 2>/dev/null | openssl x509 -noout -enddate"))
            }
        }

        if info.isRSA, let bits = info.keyBits, bits < 2048 {
            out.append(Finding(
                title: "Weak TLS certificate key (RSA \(bits)-bit)",
                severity: .high, category: "Transport Security", location: loc,
                detail: "The certificate\(cn) uses a \(bits)-bit RSA public key, below the 2048-bit minimum required by the CA/Browser Forum.",
                evidence: "Public key: RSA \(bits)-bit.",
                exploit: "RSA keys under 2048 bits are within reach of factoring attacks; recovering the private key lets an attacker impersonate the site and decrypt or tamper with all TLS traffic.",
                remediation: "Reissue the certificate with a 2048-bit (or larger) RSA key, or a modern ECDSA P-256 key, and retire the weak key.",
                reference: "CWE-326: Inadequate Encryption Strength",
                reproduction: "openssl s_client -connect \(host):\(port) -servername \(host) 2>/dev/null | openssl x509 -noout -text | grep -i 'Public-Key'"))
        }

        if let oid = info.signatureOID, let label = weakSignatureOIDs[oid] {
            out.append(Finding(
                title: "TLS certificate uses a weak signature (\(label))",
                severity: .medium, category: "Transport Security", location: loc,
                detail: "The certificate\(cn) is signed with \(label), a deprecated algorithm no longer considered collision-resistant.",
                evidence: "Signature algorithm OID: \(oid) (\(label)).",
                exploit: "MD5/SHA-1 signatures are vulnerable to chosen-prefix collisions, which have been used to forge certificates. A forged cert lets an attacker impersonate the site and man-in-the-middle its users.",
                remediation: "Reissue the certificate with a SHA-256 (or stronger) signature. All modern CAs default to SHA-256; ensure no legacy intermediate re-signs it with SHA-1.",
                reference: "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
                reproduction: "openssl s_client -connect \(host):\(port) -servername \(host) 2>/dev/null | openssl x509 -noout -text | grep -i 'Signature Algorithm'"))
        }

        if let notBefore = info.notBefore, notBefore.timeIntervalSinceNow > 0 {
            let days = Int(notBefore.timeIntervalSinceNow / 86_400)
            let when = days >= 1 ? "\(days) day(s)" : "less than a day"
            out.append(Finding(
                title: "TLS certificate is not yet valid",
                severity: .high, category: "Transport Security", location: loc,
                detail: "The server's leaf certificate\(cn) is not valid until \(fmt(notBefore)) - \(when) from now. Clients that check validity will reject the connection.",
                evidence: "notBefore: \(fmt(notBefore)) - starts \(when) in the future.",
                exploit: "A not-yet-valid certificate fails validation on correctly-configured clients (hard TLS error), and its presence usually means a misconfigured server clock or a pre-provisioned/mis-issued cert - both of which condition users to click through certificate warnings, easing MITM.",
                remediation: "Check the server's clock and the certificate's issuance window; deploy a certificate whose notBefore is in the past, and automate renewal so replacement certs activate on time.",
                reference: "CWE-298: Improper Validation of Certificate Expiration",
                reproduction: "openssl s_client -connect \(host):\(port) -servername \(host) 2>/dev/null | openssl x509 -noout -startdate"))
        }

        if let nb = info.notBefore, let na = info.notAfter {
            let lifetimeDays = Int(na.timeIntervalSince(nb) / 86_400)
            if lifetimeDays > 398 {
                out.append(Finding(
                    title: "TLS certificate has an excessive validity period (\(lifetimeDays) days)",
                    severity: .low, category: "Transport Security", location: loc,
                    detail: "The certificate\(cn) is valid for \(lifetimeDays) days (\(fmt(nb)) to \(fmt(na))), exceeding the 398-day maximum the CA/Browser Forum allows for publicly-trusted TLS certificates issued since 2020-09-01.",
                    evidence: "Validity: \(fmt(nb)) to \(fmt(na)) = \(lifetimeDays) days (> 398-day limit).",
                    exploit: "Long-lived certificates keep a compromised or mis-issued key trusted for longer and slow adoption of algorithm upgrades. Public CAs no longer issue them, so such a cert is either privately-issued or was mis-issued; browsers reject public certs whose lifetime exceeds 398 days.",
                    remediation: "Reissue with a validity of 398 days or less - ideally 90 days via automated ACME renewal - so key material and signature algorithms rotate frequently.",
                    reference: "CA/Browser Forum Baseline Requirements (398-day maximum validity)",
                    reproduction: "openssl s_client -connect \(host):\(port) -servername \(host) 2>/dev/null | openssl x509 -noout -dates"))
            }
        }

        if !info.isRSA, let bits = info.keyBits, bits < 250 {
            out.append(Finding(
                title: "Weak TLS certificate key (EC \(bits)-bit)",
                severity: .high, category: "Transport Security", location: loc,
                detail: "The certificate\(cn) uses a \(bits)-bit elliptic-curve public key, below the 256-bit field size (P-256 / secp256r1) that provides the ~128-bit security floor for ECDSA.",
                evidence: "Public key: EC \(bits)-bit.",
                exploit: "Curves under 256 bits (e.g. P-192 or P-224) deliver well under 128-bit security; recovering the private key lets an attacker impersonate the site and decrypt or tamper with the session.",
                remediation: "Reissue the certificate with a P-256 (secp256r1) or stronger curve, or a 2048-bit+ RSA key, and retire the weak key.",
                reference: "CWE-326: Inadequate Encryption Strength",
                reproduction: "openssl s_client -connect \(host):\(port) -servername \(host) 2>/dev/null | openssl x509 -noout -text | grep -iA2 'Public Key Algorithm'"))
        }

        return out
    }

    private static func fmt(_ d: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        f.timeZone = TimeZone(identifier: "UTC")
        return f.string(from: d)
    }
}
