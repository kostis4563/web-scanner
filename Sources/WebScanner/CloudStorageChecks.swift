import Foundation

enum CloudStorageChecks {

    enum Provider: String {
        case awsS3 = "Amazon S3"
        case gcs = "Google Cloud Storage"
        case azureBlob = "Azure Blob Storage"
        case doSpaces = "DigitalOcean Spaces"
    }

    struct Bucket: Hashable {
        let provider: Provider
        let name: String
        let displayHost: String
        let listURL: URL
    }


    static func extractBuckets(in text: String) -> [Bucket] {
        var out: [Bucket] = []
        var seen = Set<URL>()

        func add(_ b: Bucket?) {
            guard let b, seen.insert(b.listURL).inserted else { return }
            out.append(b)
        }

        for host in matches("([a-z0-9][a-z0-9.\\-]{1,61}[a-z0-9]\\.s3(?:[.\\-][a-z0-9\\-]+)?\\.amazonaws\\.com)", in: text) {
            let bucket = String(host.prefix(while: { $0 != "." }))
            add(makeS3(bucketHost: host, name: bucket))
        }
        for pair in matchPairs("(?<![a-z0-9._\\-])(s3(?:[.\\-][a-z0-9\\-]+)?\\.amazonaws\\.com)/([a-z0-9][a-z0-9.\\-]{1,61}[a-z0-9])", in: text) {
            add(makeS3Path(serviceHost: pair.0, name: pair.1))
        }
        for host in matches("([a-z0-9][a-z0-9.\\-]{1,61}[a-z0-9]\\.[a-z0-9\\-]+\\.digitaloceanspaces\\.com)", in: text) {
            let bucket = String(host.prefix(while: { $0 != "." }))
            add(bucketOf(provider: .doSpaces, name: bucket, host: host,
                         list: "https://\(host)/?list-type=2&max-keys=10"))
        }
        for name in matches("(?<![a-z0-9._\\-])storage\\.googleapis\\.com/([a-z0-9][a-z0-9._\\-]{1,61}[a-z0-9])", in: text) {
            add(bucketOf(provider: .gcs, name: name, host: "storage.googleapis.com/\(name)",
                         list: "https://storage.googleapis.com/\(name)?max-keys=10"))
        }
        for host in matches("([a-z0-9][a-z0-9._\\-]{1,61}[a-z0-9]\\.storage\\.googleapis\\.com)", in: text) {
            let bucket = String(host.prefix(while: { $0 != "." }))
            add(bucketOf(provider: .gcs, name: bucket, host: host,
                         list: "https://\(host)/?max-keys=10"))
        }
        for pair in matchPairs("([a-z0-9]{3,24}\\.blob\\.core\\.windows\\.net)/([a-z0-9][a-z0-9\\-]{1,61}[a-z0-9])", in: text) {
            let host = pair.0, container = pair.1
            add(bucketOf(provider: .azureBlob, name: container, host: "\(host)/\(container)",
                         list: "https://\(host)/\(container)?restype=container&comp=list"))
        }
        return out
    }

    private static func makeS3(bucketHost: String, name: String) -> Bucket? {
        bucketOf(provider: .awsS3, name: name, host: bucketHost,
                 list: "https://\(bucketHost)/?list-type=2&max-keys=10")
    }
    private static func makeS3Path(serviceHost: String, name: String) -> Bucket? {
        bucketOf(provider: .awsS3, name: name, host: "\(serviceHost)/\(name)",
                 list: "https://\(serviceHost)/\(name)?list-type=2&max-keys=10")
    }
    private static func bucketOf(provider: Provider, name: String, host: String, list: String) -> Bucket? {
        guard name.count >= 3, let u = URL(string: list) else { return nil }
        return Bucket(provider: provider, name: name, displayHost: host, listURL: u)
    }


    static func isPublicListing(_ r: HTTPResponse, bucket: Bucket) -> Bool {
        guard r.status == 200 else { return false }
        let t = r.text
        switch bucket.provider {
        case .azureBlob:
            return t.contains("<EnumerationResults")
        default:
            return t.contains("<ListBucketResult")
        }
    }

    static func exposureFinding(bucket: Bucket, response: HTTPResponse) -> Finding {
        let keys = firstKeys(in: response.text, azure: bucket.provider == .azureBlob)
        let sample = keys.isEmpty ? "(listing returned, object names omitted)"
            : keys.prefix(8).map { "• \($0)" }.joined(separator: "\n")
        return Finding(
            title: "Publicly listable \(bucket.provider.rawValue) bucket",
            severity: .high,
            category: "Cloud Storage Exposure",
            location: bucket.displayHost,
            detail: "The \(bucket.provider.rawValue) bucket \"\(bucket.name)\", referenced by this site, allows anonymous listing of its contents. Every object key in the bucket can be enumerated without credentials.",
            evidence: "Listing endpoint: \(bucket.listURL.absoluteString)\nHTTP \(response.status), anonymous request returned an object listing.\nSample object(s):\n\(sample)",
            exploit: "A listable bucket lets an attacker enumerate and download every stored object - backups, user uploads, database dumps, source, PII, secrets - and, if write access is also open, overwrite served assets to attack every visitor. Public listing is the first step attackers automate against found buckets.",
            remediation: "Block public access on the bucket (AWS: enable S3 Block Public Access and remove the public/list ACL & bucket-policy grants; GCS: remove allUsers/allAuthenticatedUsers from the bucket IAM; Azure: set the container access level to Private; Spaces: make the Space private). Serve public assets through a CDN with a restrictive origin instead of a listable bucket.",
            reference: "CWE-284 / CWE-538: Exposure of Information Through Publicly Accessible Storage",
            reproduction: "curl -s \"\(bucket.listURL.absoluteString)\"   # returns an XML object listing if public")
    }

    private static func firstKeys(in xml: String, azure: Bool) -> [String] {
        let tag = azure ? "Name" : "Key"
        return matches("<\(tag)>([^<]{1,256})</\(tag)>", in: xml, caseInsensitive: false)
    }


    private static func matches(_ pattern: String, in text: String, caseInsensitive: Bool = true) -> [String] {
        let opts: NSRegularExpression.Options = caseInsensitive ? [.caseInsensitive] : []
        guard let re = try? NSRegularExpression(pattern: pattern, options: opts) else { return [] }
        let ns = text as NSString
        let range = NSRange(location: 0, length: min(ns.length, 2_000_000))
        var out: [String] = []
        var seen = Set<String>()
        for m in re.matches(in: text, range: range) where m.numberOfRanges > 1 {
            let s = ns.substring(with: m.range(at: 1))
            let key = s.lowercased()
            if seen.insert(key).inserted { out.append(s) }
            if out.count >= 40 { break }
        }
        return out
    }

    private static func matchPairs(_ pattern: String, in text: String) -> [(String, String)] {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return [] }
        let ns = text as NSString
        let range = NSRange(location: 0, length: min(ns.length, 2_000_000))
        var out: [(String, String)] = []
        var seen = Set<String>()
        for m in re.matches(in: text, range: range) where m.numberOfRanges > 2 {
            let a = ns.substring(with: m.range(at: 1))
            let b = ns.substring(with: m.range(at: 2))
            if seen.insert((a + "/" + b).lowercased()).inserted { out.append((a, b)) }
            if out.count >= 40 { break }
        }
        return out
    }
}
