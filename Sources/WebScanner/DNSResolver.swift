import Foundation
import Network

enum DNSResolver {

    static let TYPE_A: UInt16    = 1
    static let TYPE_NS: UInt16   = 2
    static let TYPE_CNAME: UInt16 = 5
    static let TYPE_SOA: UInt16  = 6
    static let TYPE_MX: UInt16   = 15
    static let TYPE_TXT: UInt16  = 16
    static let TYPE_AAAA: UInt16 = 28
    static let TYPE_CAA: UInt16  = 257

    static let resolvers = ["1.1.1.1", "8.8.8.8"]

    struct MXRecord { let preference: Int; let host: String }

    struct Result {
        var ns: [String] = []
        var mx: [MXRecord] = []
        var txt: [String] = []
        var dmarcTxt: [String] = []
        var mtaSts: [String] = []
        var tlsRpt: [String] = []
        var bimi: [String] = []
        var dkimSelectors: [String] = []
        var caa: [String] = []
        var soaPrimary: String?
        var soaSerial: UInt32?
        var dnssec = false
        var responded = false
        var caaAnswered = false
    }

    static let dkimSelectors = ["default", "google", "selector1", "selector2",
                                "k1", "k2", "dkim", "mail", "s1", "s2", "mandrill", "mxvault"]

    struct Answer { var type: UInt16; var value: String; var mxPref: Int?; var serial: UInt32? }
    struct ParseOutput { var answers: [Answer]; var ad: Bool; var rcode: Int }

    static func enumerate(apex: String) async -> Result {
        async let nsQ     = query(apex, type: TYPE_NS)
        async let mxQ     = query(apex, type: TYPE_MX)
        async let txtQ    = query(apex, type: TYPE_TXT)
        async let caaQ    = query(apex, type: TYPE_CAA)
        async let soaQ    = query(apex, type: TYPE_SOA)
        async let dmarcQ  = query("_dmarc.\(apex)", type: TYPE_TXT)
        async let mtaQ    = query("_mta-sts.\(apex)", type: TYPE_TXT)
        async let tlsrptQ = query("_smtp._tls.\(apex)", type: TYPE_TXT)
        async let bimiQ   = query("default._bimi.\(apex)", type: TYPE_TXT)
        async let dkimQ   = probeDKIM(apex: apex)
        let (ns, mx, txt, caa, soa, dmarc, mta, tlsrpt, bimi, dkim) =
            await (nsQ, mxQ, txtQ, caaQ, soaQ, dmarcQ, mtaQ, tlsrptQ, bimiQ, dkimQ)

        var r = Result()
        if let ns  { r.responded = true; r.ns = ns.answers.filter { $0.type == TYPE_NS }.map { $0.value } }
        if let mx  { r.responded = true
            r.mx = mx.answers.filter { $0.type == TYPE_MX }
                .map { MXRecord(preference: $0.mxPref ?? 0, host: $0.value) }
                .sorted { $0.preference < $1.preference } }
        if let txt { r.responded = true; r.txt = txt.answers.filter { $0.type == TYPE_TXT }.map { $0.value } }
        if let caa { r.responded = true; r.caaAnswered = true
            r.caa = caa.answers.filter { $0.type == TYPE_CAA }.map { $0.value } }
        if let soa {
            r.responded = true
            if let s = soa.answers.first(where: { $0.type == TYPE_SOA }) {
                r.soaPrimary = s.value; r.soaSerial = s.serial
            }
        }
        if let dmarc  { r.dmarcTxt = dmarc.answers.filter { $0.type == TYPE_TXT }.map { $0.value } }
        if let mta    { r.mtaSts = mta.answers.filter { $0.type == TYPE_TXT }.map { $0.value }.filter { $0.lowercased().contains("v=stsv1") } }
        if let tlsrpt { r.tlsRpt = tlsrpt.answers.filter { $0.type == TYPE_TXT }.map { $0.value }.filter { $0.lowercased().contains("v=tlsrptv1") } }
        if let bimi   { r.bimi = bimi.answers.filter { $0.type == TYPE_TXT }.map { $0.value }.filter { $0.lowercased().contains("v=bimi1") } }
        r.dkimSelectors = dkim
        r.dnssec = (ns?.ad ?? false) || (soa?.ad ?? false)
        return r
    }

    private static func probeDKIM(apex: String) async -> [String] {
        await withTaskGroup(of: String?.self) { group in
            for sel in dkimSelectors {
                group.addTask {
                    guard let out = await query("\(sel)._domainkey.\(apex)", type: TYPE_TXT) else { return nil }
                    let hit = out.answers.contains { $0.type == TYPE_TXT &&
                        ($0.value.lowercased().contains("v=dkim1") || $0.value.lowercased().contains("k=rsa") || $0.value.lowercased().contains("p=")) }
                    return hit ? sel : nil
                }
            }
            var found: [String] = []
            for await s in group { if let s { found.append(s) } }
            return found.sorted()
        }
    }

    static func attemptAXFR(zone: String, nameserver: String) async -> (allowed: Bool, sample: [String]) {
        var msg = Data()
        msg.appendU16(UInt16.random(in: 0...UInt16.max))
        msg.appendU16(0x0000)
        msg.appendU16(1); msg.appendU16(0); msg.appendU16(0); msg.appendU16(0)
        for label in zone.split(separator: ".") {
            let bytes = Array(label.utf8).prefix(63)
            msg.append(UInt8(bytes.count)); msg.append(contentsOf: bytes)
        }
        msg.append(0)
        msg.appendU16(252)
        msg.appendU16(1)

        guard let data = await rawQueryTCP(message: msg, expectID: nil, server: nameserver),
              let out = parse(data) else { return (false, []) }

        let allowed = out.rcode == 0 && out.answers.count > 1
        let sample = out.answers.prefix(15).map { recordLabel($0) }
        return (allowed, sample)
    }

    private static func recordLabel(_ a: Answer) -> String {
        let t: String
        switch a.type {
        case TYPE_A: t = "A"; case TYPE_AAAA: t = "AAAA"; case TYPE_NS: t = "NS"
        case TYPE_CNAME: t = "CNAME"; case TYPE_MX: t = "MX"; case TYPE_TXT: t = "TXT"
        case TYPE_SOA: t = "SOA"; case TYPE_CAA: t = "CAA"; default: t = "type\(a.type)"
        }
        return "\(t) \(a.value)"
    }

    static func query(_ name: String, type: UInt16) async -> ParseOutput? {
        for server in resolvers {
            let (msg, id) = buildQuery(name: name, type: type)
            guard let data = await rawQueryUDP(message: msg, expectID: id, server: server) else { continue }
            let truncated = data.count >= 3 && (Int(data[data.startIndex + 2]) & 0x02) != 0
            if !truncated { if let out = parse(data) { return out }; continue }
            if let tcp = await rawQueryTCP(message: msg, expectID: id, server: server),
               let out = parse(tcp) { return out }
            if let out = parse(data) { return out }
        }
        return nil
    }

    private static func rawQueryUDP(message: Data, expectID: UInt16, server: String) async -> Data? {
        await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            let gate = ProbeGate()
            guard let port = NWEndpoint.Port(rawValue: 53) else { cont.resume(returning: nil); return }
            let conn = NWConnection(host: NWEndpoint.Host(server), port: port, using: .udp)
            let queue = DispatchQueue.global(qos: .utility)

            func finish(_ d: Data?) { gate.fire { conn.cancel(); cont.resume(returning: d) } }

            conn.stateUpdateHandler = { st in
                switch st {
                case .ready:
                    conn.send(content: message, completion: .contentProcessed { err in
                        if err != nil { finish(nil); return }
                        conn.receiveMessage { data, _, _, _ in
                            guard let data, data.count >= 2 else { finish(nil); return }
                            let id = (UInt16(data[data.startIndex]) << 8) | UInt16(data[data.startIndex + 1])
                            finish(id == expectID ? data : nil)
                        }
                    })
                case .failed, .cancelled:
                    finish(nil)
                default:
                    break
                }
            }
            queue.asyncAfter(deadline: .now() + .milliseconds(3000)) { finish(nil) }
            conn.start(queue: queue)
        }
    }

    private static func rawQueryTCP(message: Data, expectID: UInt16?, server: String) async -> Data? {
        await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            let gate = ProbeGate()
            guard let port = NWEndpoint.Port(rawValue: 53) else { cont.resume(returning: nil); return }
            let conn = NWConnection(host: NWEndpoint.Host(server), port: port, using: .tcp)
            let queue = DispatchQueue.global(qos: .utility)

            func finish(_ d: Data?) { gate.fire { conn.cancel(); cont.resume(returning: d) } }

            var framed = Data()
            framed.appendU16(UInt16(truncatingIfNeeded: message.count))
            framed.append(message)
            let toSend = framed

            var buf = Data()
            func readMore() {
                conn.receive(minimumIncompleteLength: 1, maximumLength: 65535) { data, _, isComplete, err in
                    if let data { buf.append(data) }
                    if buf.count >= 2 {
                        let need = (Int(buf[buf.startIndex]) << 8) | Int(buf[buf.startIndex + 1])
                        if buf.count >= 2 + need {
                            finish(buf.subdata(in: (buf.startIndex + 2)..<(buf.startIndex + 2 + need)))
                            return
                        }
                    }
                    if isComplete || err != nil { finish(nil); return }
                    readMore()
                }
            }
            conn.stateUpdateHandler = { st in
                switch st {
                case .ready:
                    conn.send(content: toSend, completion: .contentProcessed { e in
                        if e != nil { finish(nil); return }
                        readMore()
                    })
                case .failed, .cancelled:
                    finish(nil)
                default:
                    break
                }
            }
            queue.asyncAfter(deadline: .now() + .milliseconds(4000)) { finish(nil) }
            conn.start(queue: queue)
        }
    }

    private static func buildQuery(name: String, type: UInt16) -> (Data, UInt16) {
        var m = Data()
        let id = UInt16.random(in: 0...UInt16.max)
        m.appendU16(id)
        m.appendU16(0x0100)
        m.appendU16(1)
        m.appendU16(0)
        m.appendU16(0)
        m.appendU16(1)
        for label in name.split(separator: ".") {
            let bytes = Array(label.utf8).prefix(63)
            m.append(UInt8(bytes.count))
            m.append(contentsOf: bytes)
        }
        m.append(0)
        m.appendU16(type)
        m.appendU16(1)

        m.append(0)
        m.appendU16(41)
        m.appendU16(4096)
        m.appendU32(0)
        m.appendU16(0)
        return (m, id)
    }

    private static func parse(_ data: Data) -> ParseOutput? {
        let b = [UInt8](data)
        guard b.count >= 12 else { return nil }
        let flags = (Int(b[2]) << 8) | Int(b[3])
        let ad = (flags & 0x0020) != 0
        let rcode = flags & 0x000F
        let qd = (Int(b[4]) << 8) | Int(b[5])
        let an = (Int(b[6]) << 8) | Int(b[7])

        var i = 12
        for _ in 0..<qd {
            i = readName(b, i).next
            i += 4
        }

        var answers: [Answer] = []
        for _ in 0..<an {
            guard i < b.count else { break }
            i = readName(b, i).next
            guard i + 10 <= b.count else { break }
            let type = u16(b, i)
            let rdlen = Int(u16(b, i + 8))
            let rdStart = i + 10
            guard rdStart + rdlen <= b.count else { break }
            if let ans = decode(type: type, b: b, rdStart: rdStart, rdlen: rdlen) {
                answers.append(ans)
            }
            i = rdStart + rdlen
        }
        return ParseOutput(answers: answers, ad: ad, rcode: rcode)
    }

    private static func decode(type: UInt16, b: [UInt8], rdStart: Int, rdlen: Int) -> Answer? {
        switch type {
        case TYPE_A where rdlen == 4:
            return Answer(type: type, value: "\(b[rdStart]).\(b[rdStart+1]).\(b[rdStart+2]).\(b[rdStart+3])",
                          mxPref: nil, serial: nil)
        case TYPE_AAAA where rdlen == 16:
            var groups: [String] = []
            for k in stride(from: 0, to: 16, by: 2) {
                groups.append(String(format: "%x", (Int(b[rdStart+k]) << 8) | Int(b[rdStart+k+1])))
            }
            return Answer(type: type, value: groups.joined(separator: ":"), mxPref: nil, serial: nil)
        case TYPE_NS, TYPE_CNAME:
            return Answer(type: type, value: readName(b, rdStart).name, mxPref: nil, serial: nil)
        case TYPE_MX:
            let pref = Int(u16(b, rdStart))
            return Answer(type: type, value: readName(b, rdStart + 2).name, mxPref: pref, serial: nil)
        case TYPE_TXT:
            var s = ""; var k = rdStart; let end = rdStart + rdlen
            while k < end {
                let len = Int(b[k]); k += 1
                guard k + len <= end else { break }
                s += String(decoding: b[k..<k+len], as: UTF8.self); k += len
            }
            return Answer(type: type, value: s, mxPref: nil, serial: nil)
        case TYPE_SOA:
            let mname = readName(b, rdStart)
            let rname = readName(b, mname.next)
            let serial = rname.next + 4 <= b.count ? u32(b, rname.next) : nil
            return Answer(type: type, value: mname.name, mxPref: nil, serial: serial)
        case TYPE_CAA:
            guard rdlen >= 2 else { return nil }
            let tagLen = Int(b[rdStart + 1])
            let tagStart = rdStart + 2
            guard tagStart + tagLen <= rdStart + rdlen else { return nil }
            let tag = String(decoding: b[tagStart..<tagStart+tagLen], as: UTF8.self)
            let val = String(decoding: b[(tagStart+tagLen)..<(rdStart+rdlen)], as: UTF8.self)
            return Answer(type: type, value: "\(tag) \"\(val)\"", mxPref: nil, serial: nil)
        default:
            return nil
        }
    }

    private static func readName(_ b: [UInt8], _ start: Int) -> (name: String, next: Int) {
        var labels: [String] = []
        var i = start
        var next = start
        var jumped = false
        var guardCount = 0
        while i < b.count {
            guardCount += 1
            if guardCount > 128 { break }
            let len = Int(b[i])
            if len == 0 {
                i += 1
                if !jumped { next = i }
                break
            }
            if (len & 0xC0) == 0xC0 {
                guard i + 1 < b.count else { break }
                let ptr = ((len & 0x3F) << 8) | Int(b[i + 1])
                if !jumped { next = i + 2 }
                jumped = true
                i = ptr
                continue
            }
            i += 1
            guard i + len <= b.count else { break }
            labels.append(String(decoding: b[i..<i+len], as: UTF8.self))
            i += len
        }
        return (labels.joined(separator: "."), next)
    }

    private static func u16(_ b: [UInt8], _ i: Int) -> UInt16 {
        guard i + 1 < b.count else { return 0 }
        return (UInt16(b[i]) << 8) | UInt16(b[i + 1])
    }
    private static func u32(_ b: [UInt8], _ i: Int) -> UInt32 {
        guard i + 3 < b.count else { return 0 }
        return (UInt32(b[i]) << 24) | (UInt32(b[i+1]) << 16) | (UInt32(b[i+2]) << 8) | UInt32(b[i+3])
    }
}

private extension Data {
    mutating func appendU16(_ v: UInt16) { append(UInt8(v >> 8)); append(UInt8(v & 0xFF)) }
    mutating func appendU32(_ v: UInt32) {
        append(UInt8((v >> 24) & 0xFF)); append(UInt8((v >> 16) & 0xFF))
        append(UInt8((v >> 8) & 0xFF));  append(UInt8(v & 0xFF))
    }
}
