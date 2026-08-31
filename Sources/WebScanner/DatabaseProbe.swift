import Foundation
import Network

enum DatabaseProbe {

    struct Result {
        let service: String
        let port: Int

        let unauthenticated: Bool
        var version: String? = nil

        var evidence: String = ""
    }

    static func probe(host: String, port: Int, timeoutMs: Int = 2500) async -> Result? {
        switch port {
        case 6379, 6380:            return await redis(host: host, port: port, timeoutMs: timeoutMs)
        case 11211:                 return await memcached(host: host, port: port, timeoutMs: timeoutMs)
        case 5432, 5433:            return await postgres(host: host, port: port, timeoutMs: timeoutMs)
        case 27017, 27018, 27019:   return await mongodb(host: host, port: port, timeoutMs: timeoutMs)
        default:                    return nil
        }
    }

    private static func redis(host: String, port: Int, timeoutMs: Int) async -> Result? {
        guard let data = await exchange(host: host, port: port,
                                        payload: Data("INFO server\r\n".utf8), timeoutMs: timeoutMs),
              !data.isEmpty else { return nil }
        let text = String(decoding: data, as: UTF8.self)
        if text.contains("redis_version:") {
            return Result(service: "Redis", port: port, unauthenticated: true,
                          version: value(after: "redis_version:", in: text),
                          evidence: firstLines(text, 6))
        }
        return nil
    }

    private static func memcached(host: String, port: Int, timeoutMs: Int) async -> Result? {
        guard let data = await exchange(host: host, port: port,
                                        payload: Data("stats\r\n".utf8), timeoutMs: timeoutMs),
              !data.isEmpty else { return nil }
        let text = String(decoding: data, as: UTF8.self)
        guard text.contains("STAT ") else { return nil }
        return Result(service: "Memcached", port: port, unauthenticated: true,
                      version: stat(text, "version"), evidence: firstLines(text, 6))
    }

    private static func postgres(host: String, port: Int, timeoutMs: Int) async -> Result? {
        var params = Data()
        func cstr(_ s: String) { params.append(Data(s.utf8)); params.append(0) }
        cstr("user"); cstr("postgres")
        cstr("database"); cstr("postgres")
        params.append(0)

        var msg = Data()
        msg.append(be32(Int32(8 + params.count)))
        msg.append(be32(196608))
        msg.append(params)

        guard let data = await exchange(host: host, port: port, payload: msg, timeoutMs: timeoutMs),
              let first = data.first else { return nil }

        if first == UInt8(ascii: "R"), data.count >= 9 {
            let authType = readBE32(data, offset: 5)
            if authType == 0 {
                return Result(service: "PostgreSQL", port: port, unauthenticated: true,
                              evidence: "Startup for user 'postgres' returned AuthenticationOk (trust mode) - the server grants access with no password.")
            }
            return nil
        }
        return nil
    }

    private static func mongodb(host: String, port: Int, timeoutMs: Int) async -> Result? {

        var doc = Data()
        doc.append(0x10); doc.append(Data("listDatabases".utf8)); doc.append(0); doc.append(le32(1))
        doc.append(0x02); doc.append(Data("$db".utf8)); doc.append(0)
        let dbName = Data("admin".utf8)
        doc.append(le32(Int32(dbName.count + 1))); doc.append(dbName); doc.append(0)
        doc.append(0)
        var bson = Data(); bson.append(le32(Int32(doc.count + 4))); bson.append(doc)

        var body = Data()
        body.append(le32(0))
        body.append(0x00)
        body.append(bson)

        var msg = Data()
        msg.append(le32(Int32(16 + body.count)))
        msg.append(le32(1))
        msg.append(le32(0))
        msg.append(le32(2013))
        msg.append(body)

        guard let data = await exchange(host: host, port: port, payload: msg, timeoutMs: timeoutMs),
              !data.isEmpty else { return nil }
        let text = String(decoding: data, as: UTF8.self)
        if text.contains("sizeOnDisk") || (text.contains("databases") && text.contains("totalSize")) {
            return Result(service: "MongoDB", port: port, unauthenticated: true,
                          evidence: "listDatabases returned the database list with no authentication.")
        }
        return nil
    }

    private static func exchange(host: String, port: Int, payload: Data,
                                 timeoutMs: Int, maxLen: Int = 4096) async -> Data? {
        await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            guard let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
                cont.resume(returning: nil); return
            }
            let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
            let gate = ProbeGate()
            let queue = DispatchQueue(label: "webscanner.dbprobe.\(port)")
            func finish(_ d: Data?) { gate.fire { conn.cancel(); cont.resume(returning: d) } }

            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    conn.send(content: payload, completion: .contentProcessed { err in
                        if err != nil { finish(nil); return }
                        conn.receive(minimumIncompleteLength: 1, maximumLength: maxLen) { data, _, _, _ in
                            finish(data)
                        }
                    })
                case .failed, .cancelled:
                    finish(nil)
                default:
                    break
                }
            }
            queue.asyncAfter(deadline: .now() + .milliseconds(timeoutMs)) { finish(nil) }
            conn.start(queue: queue)
        }
    }

    private static func be32(_ v: Int32) -> Data {
        let u = UInt32(bitPattern: v)
        return Data([UInt8((u >> 24) & 0xff), UInt8((u >> 16) & 0xff),
                     UInt8((u >> 8) & 0xff), UInt8(u & 0xff)])
    }

    private static func le32(_ v: Int32) -> Data {
        let u = UInt32(bitPattern: v)
        return Data([UInt8(u & 0xff), UInt8((u >> 8) & 0xff),
                     UInt8((u >> 16) & 0xff), UInt8((u >> 24) & 0xff)])
    }

    private static func readBE32(_ d: Data, offset: Int) -> Int {
        let b = Array(d)
        guard offset + 4 <= b.count else { return -1 }
        return (Int(b[offset]) << 24) | (Int(b[offset + 1]) << 16)
             | (Int(b[offset + 2]) << 8) | Int(b[offset + 3])
    }

    private static func value(after key: String, in text: String) -> String? {
        guard let r = text.range(of: key) else { return nil }
        let line = text[r.upperBound...].prefix { $0 != "\r" && $0 != "\n" }
        let v = line.trimmingCharacters(in: .whitespaces)
        return v.isEmpty ? nil : v
    }

    private static func stat(_ text: String, _ key: String) -> String? {
        guard let r = text.range(of: "STAT \(key) ") else { return nil }
        let line = text[r.upperBound...].prefix { $0 != "\r" && $0 != "\n" }
        return line.isEmpty ? nil : String(line)
    }

    private static func firstLines(_ text: String, _ n: Int) -> String {
        text.split(whereSeparator: { $0 == "\r" || $0 == "\n" })
            .prefix(n).joined(separator: "\n")
    }
}
