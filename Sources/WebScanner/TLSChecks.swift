import Foundation
import Network
import Security

enum TLSChecks {

    private static let tls10 = tls_protocol_version_t(rawValue: 0x0301)!
    private static let tls11 = tls_protocol_version_t(rawValue: 0x0302)!

    private static let ssl30 = tls_protocol_version_t(rawValue: 0x0300)

    static func legacyProtocols(host: String, port: UInt16 = 443) async -> [Finding] {
        var out: [Finding] = []
        let loc = "https://\(host)" + (port == 443 ? "" : ":\(port)")

        let tls10 = await accepts(host: host, port: port, version: Self.tls10)
        let tls11 = await accepts(host: host, port: port, version: Self.tls11)

        if tls10 == true || tls11 == true {
            var enabled: [String] = []
            if tls10 == true { enabled.append("TLS 1.0") }
            if tls11 == true { enabled.append("TLS 1.1") }
            out.append(Finding(
                title: "Legacy TLS enabled (\(enabled.joined(separator: ", ")))",
                severity: .medium,
                category: "Transport Security",
                location: loc,
                detail: "The server still completes handshakes over \(enabled.joined(separator: " and ")). These protocol versions are deprecated (RFC 8996) and rely on weak cipher suites and MAC constructions.",
                evidence: "A handshake pinned to \(enabled.joined(separator: " / ")) succeeded against \(host):\(port).",
                exploit: "Legacy TLS is vulnerable to downgrade and cryptographic attacks (BEAST, POODLE, weak RC4/CBC ciphers). A network attacker can force a client onto the weakest mutually-supported version and attack the session.",
                remediation: "Disable TLS 1.0 and 1.1 on the server; require TLS 1.2+ (prefer TLS 1.3) with modern AEAD cipher suites (e.g. AES-GCM, ChaCha20-Poly1305) and disable RC4/3DES/CBC-only suites.",
                reference: "RFC 8996 / CWE-326: Inadequate Encryption Strength",
                reproduction: "openssl s_client -connect \(host):\(port) -tls1\(tls10 == true ? "" : "_1")   # handshake succeeds = legacy TLS accepted"))
        }

        var ssl30: Bool? = nil
        if let v = Self.ssl30 { ssl30 = await accepts(host: host, port: port, version: v) }
        if ssl30 == true {
            out.append(Finding(
                title: "SSL 3.0 enabled (POODLE)",
                severity: .high,
                category: "Transport Security",
                location: loc,
                detail: "The server completes handshakes over SSL 3.0, an obsolete protocol deprecated by RFC 7568 whose CBC cipher suites are structurally broken by the POODLE attack.",
                evidence: "A handshake pinned to SSL 3.0 (0x0300) succeeded against \(host):\(port).",
                exploit: "SSL 3.0's CBC padding is non-deterministic, enabling POODLE (CVE-2014-3566): an attacker who can run script in the victim's browser and force a downgrade to SSLv3 recovers plaintext (e.g. session cookies) one byte at a time.",
                remediation: "Disable SSL 3.0 entirely and require TLS 1.2+ (prefer TLS 1.3) with modern AEAD cipher suites. There is no safe configuration of SSL 3.0.",
                reference: "CVE-2014-3566 (POODLE) / RFC 7568 / CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
                reproduction: "openssl s_client -connect \(host):\(port) -ssl3   # handshake succeeds = SSLv3 accepted"))
        }
        return out
    }

    private static func accepts(host: String, port: UInt16,
                               version: tls_protocol_version_t) async -> Bool? {
        await withCheckedContinuation { (cont: CheckedContinuation<Bool?, Never>) in
            guard let nwPort = NWEndpoint.Port(rawValue: port) else {
                cont.resume(returning: nil); return
            }
            let gate = ProbeGate()

            let tls = NWProtocolTLS.Options()
            let sec = tls.securityProtocolOptions
            sec_protocol_options_set_min_tls_protocol_version(sec, version)
            sec_protocol_options_set_max_tls_protocol_version(sec, version)
            if #available(macOS 11.0, *) {
                sec_protocol_options_set_tls_server_name(sec, host)
            }

            sec_protocol_options_set_verify_block(sec, { _, _, complete in
                complete(true)
            }, DispatchQueue.global())

            let params = NWParameters(tls: tls)
            let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: params)
            let queue = DispatchQueue.global(qos: .utility)

            func finish(_ value: Bool?) {
                gate.fire {
                    conn.cancel()
                    cont.resume(returning: value)
                }
            }

            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    finish(true)
                case .failed:
                    finish(false)
                case .waiting:
                    finish(nil)
                default:
                    break
                }
            }
            queue.asyncAfter(deadline: .now() + .milliseconds(4000)) { finish(nil) }
            conn.start(queue: queue)
        }
    }
}
