import Foundation
import Network

enum DDoSExposure {

    static let category = "DDoS Exposure"

    struct Vector {
        let name: String
        let port: Int
        let probe: Data
        let factor: String
        let severity: Severity
        let why: String
        let fix: String
        let reference: String
        let cmd: String
    }

    static func assess(host: String, ip: String, openTCPPorts: [Int]) async -> [Finding] {
        var out: [Finding] = []
        let vectors = Self.vectors

        let results: [(Vector, Int?)] = await withTaskGroup(of: (Vector, Int?).self) { group in
            for v in vectors {
                group.addTask { (v, await probe(ip: ip, port: v.port, payload: v.probe, timeoutMs: 2200)) }
            }
            var acc: [(Vector, Int?)] = []
            for await r in group { acc.append(r) }
            return acc
        }

        var found: [(Vector, Int)] = []
        for (v, bytes) in results {

            guard let bytes, bytes >= v.probe.count else { continue }
            found.append((v, bytes))
            out.append(vectorFinding(ip: ip, v: v, respBytes: bytes))
        }

        out.append(summaryFinding(host: host, ip: ip, openTCPPorts: openTCPPorts, found: found))
        return out
    }

    private static func vectorFinding(ip: String, v: Vector, respBytes: Int) -> Finding {
        let ratio = v.probe.isEmpty ? 0 : Double(respBytes) / Double(v.probe.count)
        return Finding(
            title: "\(v.name) reflection/amplification vector exposed (UDP \(v.port))",
            severity: v.severity,
            category: category,
            location: "\(ip):\(v.port)/udp",
            detail: "\(v.name) is reachable over UDP port \(v.port) and answered an unsolicited request. \(v.why)",
            evidence: """
                IP: \(ip)
                Protocol: UDP
                Port: \(v.port)
                Single-packet test: \(v.probe.count) bytes sent → \(respBytes) bytes returned (≈\(String(format: "%.1f", ratio))x on one packet)
                Known amplification for \(v.name): \(v.factor)
                """,
            exploit: "In a reflected DDoS the attacker spoofs a victim's source IP and sends small \(v.name) requests here; this service reflects a much larger reply to the victim. The host becomes an unwitting amplifier - burning its own bandwidth, harming a third party, and risking blocklisting of \(ip).",
            remediation: v.fix,
            reference: v.reference,
            reproduction: v.cmd.replacingOccurrences(of: "{ip}", with: ip)
                .replacingOccurrences(of: "{port}", with: "\(v.port)"))
    }

    private static func summaryFinding(host: String, ip: String,
                                       openTCPPorts: [Int], found: [(Vector, Int)]) -> Finding {
        let tcpList = openTCPPorts.sorted()
        let tcpText = tcpList.isEmpty ? "none observed"
            : tcpList.map { "\($0)/tcp" }.joined(separator: ", ")
        let udpText = found.isEmpty ? "none detected"
            : found.map { "\($0.0.name) \($0.0.port)/udp (\($0.0.factor))" }.joined(separator: ", ")

        let hasAmp = !found.isEmpty
        let sev: Severity = hasAmp ? .medium : .info

        return Finding(
            title: "DDoS exposure summary for \(host)",
            severity: sev,
            category: category,
            location: ip,
            detail: "Overview of how this host could be involved in a denial-of-service attack, as a direct target (TCP/UDP flood) or - if any amplifier is open - as a reflector abused against others.",
            evidence: """
                Target IP: \(ip)
                Reachable TCP ports (potential flood / state-exhaustion targets): \(tcpText)
                UDP reflection/amplification vectors: \(udpText)
                """,
            exploit: hasAmp
                ? "Open amplifiers let attackers reflect traffic off this host at others. Separately, any directly reachable TCP/UDP port can be targeted by a volumetric or connection-exhaustion flood aimed at this IP."
                : "No open UDP amplifiers were found. Any directly reachable TCP/UDP port can still be targeted by a volumetric or connection-exhaustion flood aimed at this IP.",
            remediation: "Firewall every UDP service you don't intentionally expose, and disable amplification features (DNS recursion for the public, NTP monlist, memcached UDP, SSDP, chargen/QOTD). Put the origin behind a DDoS-scrubbing / CDN provider and restrict the origin firewall to it so volumetric floods never reach \(ip) directly. Enable SYN cookies and connection rate limits on exposed TCP services.",
            reference: "CISA Alert TA14-017A: UDP-Based Amplification Attacks",
            reproduction: "sudo nmap -sU -sV -p 19,53,111,123,161,1900,11211 \(ip)   # inspect UDP services")
    }

    private static func probe(ip: String, port: Int, payload: Data, timeoutMs: Int) async -> Int? {
        await withCheckedContinuation { (cont: CheckedContinuation<Int?, Never>) in
            let gate = ProbeGate()
            guard let p = NWEndpoint.Port(rawValue: UInt16(port)) else { cont.resume(returning: nil); return }
            let conn = NWConnection(host: NWEndpoint.Host(ip), port: p, using: .udp)
            let queue = DispatchQueue.global(qos: .utility)

            func finish(_ n: Int?) { gate.fire { conn.cancel(); cont.resume(returning: n) } }

            conn.stateUpdateHandler = { st in
                switch st {
                case .ready:
                    conn.send(content: payload, completion: .contentProcessed { err in
                        if err != nil { finish(nil); return }
                        conn.receiveMessage { data, _, _, _ in finish(data?.count) }
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

    static let vectors: [Vector] = [
        Vector(name: "DNS (open resolver)", port: 53, probe: dnsProbe(),
               factor: "up to ~54x", severity: .high,
               why: "It answered a recursive query, so it acts as an open DNS resolver for anyone on the internet.",
               fix: "Disable open recursion (serve recursion only to your own clients), or run an authoritative-only server. Add response-rate-limiting (RRL).",
               reference: "CWE-406 / US-CERT TA13-088A (Open DNS Resolvers)",
               cmd: "dig @{ip} ANY google.com +notcp   # large answer = open resolver"),
        Vector(name: "NTP (monlist)", port: 123, probe: Data([0x17, 0x00, 0x03, 0x2a, 0, 0, 0, 0]),
               factor: "up to ~556x", severity: .high,
               why: "It responded to a mode-7 monlist request (CVE-2013-5211), one of the strongest amplifiers.",
               fix: "Upgrade ntpd to 4.2.7p26+ and disable mode 6/7 queries (`disable monitor`), or firewall UDP/123 from the public internet.",
               reference: "CVE-2013-5211 / CWE-406",
               cmd: "ntpdc -n -c monlist {ip}   # returns client list = vulnerable"),
        Vector(name: "memcached", port: 11211, probe: memcachedProbe(),
               factor: "up to ~51,000x", severity: .high,
               why: "memcached is answering over UDP - the vector behind the record-breaking 2018 reflection attacks.",
               fix: "Disable UDP (`-U 0`), bind to localhost, and firewall port 11211. memcached should never face the internet.",
               reference: "CVE-2018-1000115 / CWE-406",
               cmd: "printf '\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00stats\\r\\n' | nc -u -w1 {ip} 11211"),
        Vector(name: "CharGen", port: 19, probe: Data([0x01]),
               factor: "up to ~358x", severity: .high,
               why: "The legacy Character Generator service replies with a large character stream to a 1-byte request.",
               fix: "Disable the chargen service (it has no modern use): remove/comment it in inetd/xinetd and firewall UDP/19.",
               reference: "CWE-406 / TA14-017A",
               cmd: "printf 'x' | nc -u -w1 {ip} 19 | wc -c"),
        Vector(name: "SSDP / UPnP", port: 1900, probe: ssdpProbe(),
               factor: "up to ~30x", severity: .medium,
               why: "A UPnP/SSDP service replied to an M-SEARCH discovery - a very common consumer-device amplifier.",
               fix: "Do not expose UPnP/SSDP (UDP/1900) to the internet; disable UPnP on internet-facing routers/devices and firewall the port.",
               reference: "CWE-406 / TA14-017A",
               cmd: "nmap -sU -p 1900 --script=upnp-info {ip}"),
        Vector(name: "SNMP", port: 161, probe: snmpProbe(),
               factor: "up to ~6x (plus data leak)", severity: .medium,
               why: "SNMP answered a GET with the 'public' community, exposing device data and acting as a reflector.",
               fix: "Firewall UDP/161, disable SNMP v1/v2c, change default community strings, and use SNMPv3 with auth+priv.",
               reference: "CWE-406 / CWE-284",
               cmd: "snmpget -v2c -c public {ip} 1.3.6.1.2.1.1.1.0"),
        Vector(name: "QOTD", port: 17, probe: Data([0x01]),
               factor: "up to ~140x", severity: .medium,
               why: "The legacy Quote-of-the-Day service replied to a tiny request - a usable reflection vector.",
               fix: "Disable the qotd service and firewall UDP/17; it has no legitimate modern use.",
               reference: "CWE-406 / TA14-017A",
               cmd: "printf 'x' | nc -u -w1 {ip} 17"),
        Vector(name: "CLDAP", port: 389, probe: cldapProbe(),
               factor: "up to ~70x", severity: .high,
               why: "Connectionless LDAP (Active Directory) answered a rootDSE query over UDP - a heavily-abused amplifier.",
               fix: "Never expose CLDAP (UDP/389) to the internet. Firewall it to the internal network; domain controllers must not be publicly reachable.",
               reference: "CWE-406 / TA14-017A",
               cmd: "nmap -sU -p 389 --script=ldap-rootdse {ip}"),
        Vector(name: "WS-Discovery", port: 3702, probe: wsdProbe(),
               factor: "up to ~500x", severity: .high,
               why: "A WS-Discovery service (IP cameras, printers, IoT) answered a SOAP Probe - one of the strongest UDP amplifiers.",
               fix: "Block UDP/3702 at the perimeter; WS-Discovery is a LAN protocol and should never be internet-facing. Disable it on devices that don't need it.",
               reference: "CVE-2019-9875 class / TA14-017A",
               cmd: "nmap -sU -p 3702 {ip}"),
        Vector(name: "RPCbind / Portmap", port: 111, probe: rpcbindProbe(),
               factor: "up to ~28x", severity: .medium,
               why: "The portmapper answered a DUMP call, listing registered RPC services (often NFS) and acting as a reflector.",
               fix: "Firewall UDP/TCP 111 from untrusted networks and disable rpcbind if no RPC services are needed.",
               reference: "CWE-406 / TA14-017A",
               cmd: "rpcinfo -p {ip}"),
        Vector(name: "TFTP", port: 69, probe: tftpProbe(),
               factor: "up to ~60x", severity: .medium,
               why: "A TFTP server responded to a read request - it can be used for reflection and often exposes bootstrap files.",
               fix: "Firewall UDP/69 from the internet; TFTP is unauthenticated and should stay on trusted management networks only.",
               reference: "CWE-406 / TA14-017A",
               cmd: "tftp {ip} -c get a   # or: nmap -sU -p 69 {ip}"),
        Vector(name: "NetBIOS-NS", port: 137, probe: netbiosProbe(),
               factor: "up to ~4x (plus host info)", severity: .low,
               why: "NetBIOS Name Service answered a node-status query, leaking the machine/workgroup name and acting as a small reflector.",
               fix: "Firewall UDP/137 (and 138/139/445) from the internet; disable NetBIOS over TCP/IP on internet-facing interfaces.",
               reference: "CWE-406 / CWE-200",
               cmd: "nmblookup -A {ip}"),
        Vector(name: "mDNS", port: 5353, probe: mdnsProbe(),
               factor: "up to ~10x (plus service list)", severity: .low,
               why: "Multicast DNS answered a unicast service query, disclosing advertised services - it should never be routable off-link.",
               fix: "Block UDP/5353 at the perimeter; mDNS is a link-local protocol and must not traverse the internet.",
               reference: "CWE-406 / CWE-200",
               cmd: "dig @{ip} -p 5353 _services._dns-sd._udp.local PTR"),
        Vector(name: "CoAP", port: 5683, probe: coapProbe(),
               factor: "up to ~34x", severity: .high,
               why: "A CoAP (Constrained Application Protocol) IoT endpoint answered an unsolicited /.well-known/core discovery over UDP - a strong, actively-abused amplifier (Netscout measured ~569-byte replies to a 21-byte request).",
               fix: "Do not expose UDP/5683 to the internet; require DTLS (coaps on UDP/5684), disable resource discovery for untrusted clients, and firewall the port to trusted management networks.",
               reference: "CWE-406 / Netscout ASERT: CoAP Attacks In The Wild",
               cmd: "nmap -sU -p 5683 --script=coap-resources {ip}   # dumps /.well-known/core"),
        Vector(name: "Ubiquiti discovery", port: 10001, probe: ubiquitiProbe(),
               factor: "up to ~35x (plus device info)", severity: .high,
               why: "A Ubiquiti device answered its discovery protocol over UDP, reflecting a large 'pong' reply and leaking model, firmware version and MAC/IP details usable for targeted attacks.",
               fix: "Disable the discovery service or firewall UDP/10001 from the internet, and update firmware (Ubiquiti hardened this service after the 2019 disclosure).",
               reference: "CWE-406 / Rapid7: Ubiquiti Discovery Service Exposures (2019)",
               cmd: "printf '\\x01\\x00\\x00\\x00' | nc -u -w1 {ip} 10001 | wc -c"),
        Vector(name: "Plex Media Server (GDM)", port: 32414, probe: plexGdmProbe(),
               factor: "up to ~4.7x", severity: .low,
               why: "A Plex Media Server answered a GDM (G'Day Mate) discovery request over UDP - a small but real reflector exposed when Plex auto-opens a UPnP forward (Netscout 'PMSSDP').",
               fix: "Do not expose UDP/32414 (or 32410/32412/32413) to the internet; turn off 'GDM network discovery' in Plex and disable UPnP port-forwarding on the router.",
               reference: "CWE-406 / Netscout ASERT: Plex Media SSDP (PMSSDP) reflection",
               cmd: "printf 'M-SEARCH * HTTP/1.0\\r\\n\\r\\n' | nc -u -w1 {ip} 32414 | wc -c"),
        Vector(name: "Steam / Source A2S_INFO", port: 27015, probe: a2sInfoProbe(),
               factor: "up to ~5x", severity: .medium,
               why: "A Source-engine game server answered an unsolicited A2S_INFO query over UDP, reflecting server metadata; the classic A2S reflection loop between two servers can drive far higher volumes.",
               fix: "Rate-limit A2S queries or front the server with a query cache/proxy, restrict UDP/27015 to expected players, and keep the game build patched (the A2S challenge/loop fix landed in later Source updates).",
               reference: "CWE-406 / Netscout: Reflection/Amplification (Source Engine Query)",
               cmd: "printf '\\xff\\xff\\xff\\xffTSource Engine Query\\x00' | nc -u -w1 {ip} 27015 | wc -c"),
        Vector(name: "SIP", port: 5060, probe: sipOptionsProbe(),
               factor: "up to ~3x (plus PBX/vendor info)", severity: .low,
               why: "A SIP endpoint (PBX / VoIP gateway) answered an unsolicited OPTIONS request over UDP - a modest reflector that also leaks the Server/User-Agent banner and supported methods for reconnaissance.",
               fix: "Firewall UDP/5060 to known SIP peers/providers, drop unauthenticated OPTIONS scans, strip Server/User-Agent banners, and place the PBX behind a session border controller (SBC).",
               reference: "CWE-406 / CWE-200",
               cmd: "nmap -sU -p 5060 --script=sip-methods {ip}   # or: sipsak -s sip:nm@{ip} -vv"),
    ]

    private static func dnsProbe() -> Data {

        var m = Data([0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        for label in ["google", "com"] { m.append(UInt8(label.count)); m.append(contentsOf: label.utf8) }
        m.append(0)
        m.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
        return m
    }

    private static func memcachedProbe() -> Data {

        var m = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])
        m.append(contentsOf: "stats\r\n".utf8)
        return m
    }

    private static func ssdpProbe() -> Data {
        Data(("M-SEARCH * HTTP/1.1\r\n" +
              "HOST:239.255.255.250:1900\r\n" +
              "MAN:\"ssdp:discover\"\r\n" +
              "MX:2\r\n" +
              "ST:ssdp:all\r\n\r\n").utf8)
    }

    private static func snmpProbe() -> Data {

        Data([
            0x30, 0x29, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
            0xa0, 0x1c, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
            0x05, 0x00,
        ])
    }

    private static func cldapProbe() -> Data {

        Data([
            0x30, 0x84, 0x00, 0x00, 0x00, 0x2d, 0x02, 0x01, 0x01, 0x63, 0x84, 0x00, 0x00, 0x00,
            0x24, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01,
            0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c,
            0x61, 0x73, 0x73, 0x30, 0x84, 0x00, 0x00, 0x00, 0x00,
        ])
    }

    private static func rpcbindProbe() -> Data {

        Data([
            0x72, 0x6e, 0x64, 0x21,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x01, 0x86, 0xa0,
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
    }

    private static func tftpProbe() -> Data {

        var m = Data([0x00, 0x01])
        m.append(contentsOf: "a".utf8); m.append(0)
        m.append(contentsOf: "octet".utf8); m.append(0)
        return m
    }

    private static func netbiosProbe() -> Data {

        var m = Data([0xa2, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        m.append(0x20)
        m.append(contentsOf: "CK".utf8)
        m.append(contentsOf: Array(repeating: UInt8(ascii: "A"), count: 30))
        m.append(0x00)
        m.append(contentsOf: [0x00, 0x21, 0x00, 0x01])
        return m
    }

    private static func mdnsProbe() -> Data {

        var m = Data([0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        for label in ["_services", "_dns-sd", "_udp", "local"] {
            m.append(UInt8(label.count)); m.append(contentsOf: label.utf8)
        }
        m.append(0)
        m.append(contentsOf: [0x00, 0x0c, 0x00, 0x01])
        return m
    }

    private static func wsdProbe() -> Data {

        let xml = """
            <?xml version="1.0" encoding="utf-8"?>\
            <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" \
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" \
            xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">\
            <soap:Header>\
            <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>\
            <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>\
            <wsa:MessageID>urn:uuid:0a6dc791-2be6-4991-9af1-454778a1917a</wsa:MessageID>\
            </soap:Header>\
            <soap:Body><wsd:Probe/></soap:Body>\
            </soap:Envelope>
            """
        return Data(xml.utf8)
    }

    private static func coapProbe() -> Data {

        var m = Data([0x40, 0x01, 0x13, 0x37])
        m.append(0xbb)
        m.append(contentsOf: ".well-known".utf8)
        m.append(0x04)
        m.append(contentsOf: "core".utf8)
        return m
    }

    private static func ubiquitiProbe() -> Data {

        Data([0x01, 0x00, 0x00, 0x00])
    }

    private static func plexGdmProbe() -> Data {

        Data("M-SEARCH * HTTP/1.0\r\n\r\n".utf8)
    }

    private static func a2sInfoProbe() -> Data {

        var m = Data([0xff, 0xff, 0xff, 0xff, 0x54])
        m.append(contentsOf: "Source Engine Query".utf8)
        m.append(0)
        return m
    }

    private static func sipOptionsProbe() -> Data {

        Data(("OPTIONS sip:nm@nm SIP/2.0\r\n" +
              "Via: SIP/2.0/UDP nm;branch=z9hG4bK-1337;rport\r\n" +
              "Max-Forwards: 70\r\n" +
              "From: <sip:nm@nm>;tag=1337\r\n" +
              "To: <sip:nm@nm>\r\n" +
              "Call-ID: 1337-webscanner\r\n" +
              "CSeq: 1 OPTIONS\r\n" +
              "Content-Length: 0\r\n\r\n").utf8)
    }
}
