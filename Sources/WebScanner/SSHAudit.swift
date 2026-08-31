import Foundation
import Network

enum SSHAudit {

    struct Result {
        var banner: String?
        var kex: [String] = []
        var hostKeys: [String] = []
        var ciphers: [String] = []
        var macs: [String] = []
        var compression: [String] = []

        var hasKexInit: Bool { !kex.isEmpty || !hostKeys.isEmpty || !ciphers.isEmpty }
    }

    static func audit(host: String, port: Int, timeoutMs: Int = 2500) async -> Result? {
        guard let raw = await handshake(host: host, port: port, timeoutMs: timeoutMs) else {
            return nil
        }
        let bytes = [UInt8](raw)
        guard let (banner, afterBanner) = splitBanner(bytes) else { return nil }
        var result = Result()
        result.banner = banner.trimmingCharacters(in: .whitespacesAndNewlines)
        parseKexInit(Array(bytes[afterBanner...]), into: &result)
        return result
    }

    private struct Weak { let name: String; let severity: Severity; let reason: String }

    static func findings(host: String, port: Int, result: Result) -> [Finding] {
        guard result.hasKexInit else { return [] }
        let loc = "\(host):\(port)"

        let weakKex     = result.kex.compactMap { a in classifyKex(a).map { Weak(name: a, severity: $0.0, reason: $0.1) } }
        let weakHostKey = result.hostKeys.compactMap { a in classifyHostKey(a).map { Weak(name: a, severity: $0.0, reason: $0.1) } }
        let weakCipher  = result.ciphers.compactMap { a in classifyCipher(a).map { Weak(name: a, severity: $0.0, reason: $0.1) } }
        let weakMac     = result.macs.compactMap { a in classifyMac(a).map { Weak(name: a, severity: $0.0, reason: $0.1) } }

        let allWeak = weakKex + weakHostKey + weakCipher + weakMac
        guard !allWeak.isEmpty else { return [] }

        let severity = allWeak.map(\.severity).min() ?? .low

        var evidence = ""
        func section(_ title: String, _ weak: [Weak], offered: [String]) {
            guard !weak.isEmpty else { return }
            evidence += "\(title):\n"
            for w in weak { evidence += "  • \(w.name) - \(w.reason) [\(w.severity.label)]\n" }
            evidence += "  offered: \(offered.joined(separator: ", "))\n"
        }
        section("Key exchange", weakKex, offered: result.kex)
        section("Host key", weakHostKey, offered: result.hostKeys)
        section("Ciphers", weakCipher, offered: result.ciphers)
        section("MACs", weakMac, offered: result.macs)
        if let b = result.banner, !b.isEmpty { evidence = "Server: \(b)\n\n" + evidence }

        let finding = Finding(
            title: "SSH server offers weak or deprecated algorithms",
            severity: severity,
            category: "Transport Security",
            location: loc,
            detail: "The SSH service at \(loc) advertises cryptographic algorithms in its KEXINIT that are considered weak or deprecated. During negotiation the client and server pick the first mutually-supported option from each list, so a network attacker able to influence the negotiation can push the session onto the weakest algorithm both sides still allow.",
            evidence: evidence.trimmingCharacters(in: .newlines),
            exploit: "SHA-1 / 1024-bit key exchange and host-key algorithms are susceptible to downgrade and precomputation attacks; CBC-mode ciphers and MD5/SHA-1 MACs allow plaintext-recovery and forgery (e.g. CVE-2008-5161, the SSH CBC plaintext-recovery flaw). Removing strong options is not required to exploit this - an attacker only needs the weak option to remain enabled.",
            remediation: """
            Restrict the server to modern algorithms in /etc/ssh/sshd_config and reload sshd:
              KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
              HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
              Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
              MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
            While hardening SSH, also set 'PasswordAuthentication no' (use keys) and 'PermitRootLogin no' to remove the brute-force surface, and keep OpenSSH patched.
            """,
            reference: "CWE-326: Inadequate Encryption Strength / SSH hardening (ssh-audit, Mozilla OpenSSH guidelines)",
            reproduction: "ssh-audit \(host) -p \(port)   # or: nmap --script ssh2-enum-algos -p \(port) \(host)")

        return [finding]
    }

    private static func classifyKex(_ a: String) -> (Severity, String)? {
        let l = a.lowercased()
        if l == "diffie-hellman-group1-sha1" { return (.medium, "1024-bit MODP group with SHA-1 (Logjam-class)") }
        if l == "rsa1024-sha1" { return (.medium, "1024-bit RSA with SHA-1") }
        if l.hasPrefix("gss-") && l.contains("group1-") { return (.medium, "weak 1024-bit GSS-API key exchange") }
        if l.hasSuffix("-sha1") || l.hasSuffix("sha1") { return (.low, "SHA-1 based key exchange") }
        if l.hasPrefix("gss-") && l.contains("-sha1-") { return (.low, "SHA-1 based GSS-API key exchange") }
        if l.hasPrefix("sntrup4591761") { return (.info, "superseded experimental NTRU Prime key exchange (replaced by sntrup761x25519-sha512)") }
        return nil
    }

    private static func classifyHostKey(_ a: String) -> (Severity, String)? {
        let l = a.lowercased()
        if l.hasPrefix("ssh-dss") { return (.medium, "DSA 1024-bit (disabled by default since OpenSSH 7.0)") }
        if l == "ssh-rsa" || l == "ssh-rsa-cert-v01@openssh.com" {
            return (.low, "RSA with SHA-1 signature (deprecated, off by default since OpenSSH 8.8)")
        }
        if l.hasPrefix("x509v3-") && l.contains("dss") { return (.medium, "X.509 DSA host key (1024-bit DSA, RFC 6187 legacy)") }
        return nil
    }

    private static func classifyCipher(_ a: String) -> (Severity, String)? {
        let l = a.lowercased()
        if l == "none" { return (.high, "no encryption") }
        if l.hasPrefix("arcfour") { return (.medium, "RC4 stream cipher (biased keystream)") }
        if l == "3des-cbc" || l == "des-cbc" || l == "des" { return (.medium, "DES/3DES, 64-bit block") }
        if l == "blowfish-cbc" || l == "cast128-cbc" { return (.medium, "legacy 64-bit block cipher") }
        if l.hasSuffix("-cbc") { return (.low, "CBC mode (plaintext-recovery risk, CVE-2008-5161)") }
        if l.contains("-cbc@") { return (.low, "CBC mode (plaintext-recovery risk, CVE-2008-5161)") }
        return nil
    }

    private static func classifyMac(_ a: String) -> (Severity, String)? {
        let l = a.lowercased()
        if l == "none" { return (.high, "no message integrity") }
        if l.hasPrefix("hmac-md5") { return (.medium, "MD5-based MAC") }
        if l.hasPrefix("umac-64") { return (.medium, "64-bit authentication tag") }
        if l.hasSuffix("-96") { return (.low, "truncated 96-bit MAC") }
        if l.hasPrefix("hmac-sha1") { return (.low, "SHA-1 based MAC") }
        if l.hasPrefix("hmac-ripemd160") { return (.low, "legacy RIPEMD-160 MAC (deprecated)") }
        return nil
    }

    private final class ByteBuffer: @unchecked Sendable { var data = Data() }

    private static func handshake(host: String, port: Int, timeoutMs: Int) async -> Data? {
        await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            let gate = ProbeGate()
            guard let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
                cont.resume(returning: nil); return
            }
            let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
            let queue = DispatchQueue(label: "webscanner.sshaudit")
            let buffer = ByteBuffer()

            func finish(_ d: Data?) {
                gate.fire { conn.cancel(); cont.resume(returning: d) }
            }

            func haveFullPacket() -> Bool {
                let bytes = [UInt8](buffer.data)
                guard let (_, after) = splitBanner(bytes) else { return false }
                let rest = bytes.count - after
                guard rest >= 4 else { return false }
                let len = Int(be32(bytes, after))
                return len > 0 && len < 35000 && rest >= 4 + len
            }

            func receiveLoop() {
                conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, isComplete, err in
                    if let data, !data.isEmpty { buffer.data.append(data) }
                    if haveFullPacket() || buffer.data.count > 16384 {
                        finish(buffer.data); return
                    }
                    if isComplete || err != nil {
                        finish(buffer.data.isEmpty ? nil : buffer.data); return
                    }
                    receiveLoop()
                }
            }

            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:

                    let ident = "SSH-2.0-WebScanner_audit\r\n"
                    conn.send(content: ident.data(using: .utf8), completion: .contentProcessed { _ in })
                    receiveLoop()
                case .failed, .cancelled:
                    finish(buffer.data.isEmpty ? nil : buffer.data)
                case .waiting:
                    finish(nil)
                default:
                    break
                }
            }
            queue.asyncAfter(deadline: .now() + .milliseconds(timeoutMs)) {
                finish(buffer.data.isEmpty ? nil : buffer.data)
            }
            conn.start(queue: queue)
        }
    }

    private static func splitBanner(_ bytes: [UInt8]) -> (String, Int)? {
        var lineStart = 0
        var i = 0
        while i < bytes.count {
            if bytes[i] == 0x0A {
                let lineEnd = (i > lineStart && bytes[i - 1] == 0x0D) ? i - 1 : i
                let slice = Array(bytes[lineStart..<lineEnd])
                if slice.count >= 4, slice[0] == 0x53, slice[1] == 0x53, slice[2] == 0x48, slice[3] == 0x2D {
                    return (String(decoding: slice, as: UTF8.self), i + 1)
                }
                lineStart = i + 1
            }
            i += 1
        }
        return nil
    }

    private static func parseKexInit(_ p: [UInt8], into result: inout Result) {
        guard p.count >= 6 else { return }
        let len = Int(be32(p, 0))
        guard len > 0, p.count >= 4 + len else { return }
        let padLen = Int(p[4])
        let payloadLen = len - padLen - 1
        guard payloadLen > 0, 5 + payloadLen <= p.count else { return }
        let payload = Array(p[5..<(5 + payloadLen)])

        guard payload.count > 17, payload[0] == 20 else { return }

        var off = 17
        func nextList() -> [String]? {
            guard off + 4 <= payload.count else { return nil }
            let l = Int(be32(payload, off)); off += 4
            guard l >= 0, off + l <= payload.count else { return nil }
            let s = String(decoding: payload[off..<(off + l)], as: UTF8.self); off += l
            return s.isEmpty ? [] : s.split(separator: ",").map(String.init)
        }

        result.kex        = nextList() ?? []
        result.hostKeys   = nextList() ?? []
        let encCS         = nextList() ?? []
        let encSC         = nextList() ?? []
        result.ciphers    = encSC.isEmpty ? encCS : encSC
        let macCS         = nextList() ?? []
        let macSC         = nextList() ?? []
        result.macs       = macSC.isEmpty ? macCS : macSC
        let comCS         = nextList() ?? []
        _ = nextList()
        result.compression = comCS
    }

    private static func be32(_ b: [UInt8], _ off: Int) -> UInt32 {
        (UInt32(b[off]) << 24) | (UInt32(b[off + 1]) << 16) | (UInt32(b[off + 2]) << 8) | UInt32(b[off + 3])
    }
}
