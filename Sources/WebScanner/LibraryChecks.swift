import Foundation

enum LibraryChecks {

    private struct Lib {
        let name: String

        let marker: String
        let fileRegexes: [NSRegularExpression]
        let contentRegexes: [NSRegularExpression]
        let safeMin: [Int]
        let safeMinLabel: String
        let severity: Severity
        let issue: String
        let reference: String
    }

    struct Hit {
        let name: String
        let version: [Int]
        let versionLabel: String
        let safeMinLabel: String
        let severity: Severity
        let issue: String
        let reference: String
        let source: String
    }

    private static func rx(_ pattern: String) -> NSRegularExpression {
        try! NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
    }
    private static let ver = "([0-9]+\\.[0-9]+(?:\\.[0-9]+)?)"

    private static let libs: [Lib] = [
        Lib(name: "jQuery", marker: "jquery",
            fileRegexes: [rx("jquery[-.]" + ver + "(?:\\.min)?\\.js"), rx("jquery[^0-9\"']{0,8}[?&]ver=" + ver)],
            contentRegexes: [rx("jQuery v" + ver), rx("\\.jquery\\s*=\\s*[\"']" + ver)],
            safeMin: [3, 5, 0], safeMinLabel: "3.5.0", severity: .medium,
            issue: "jQuery < 3.5.0 is affected by cross-site scripting via htmlPrefilter (CVE-2020-11022/11023) and, in older releases, prototype pollution (CVE-2019-11358) and $()-selector XSS.",
            reference: "CVE-2020-11022 / CWE-1104: Use of Unmaintained Third-Party Components"),

        Lib(name: "jQuery UI", marker: "jquery ui",
            fileRegexes: [rx("jquery-ui[-.]" + ver)],
            contentRegexes: [rx("jQuery UI[ -]" + ver)],
            safeMin: [1, 13, 2], safeMinLabel: "1.13.2", severity: .medium,
            issue: "jQuery UI < 1.13.2 has multiple XSS flaws in the datepicker, dialog and tooltip widgets (CVE-2021-41182/41183/41184, CVE-2022-31160).",
            reference: "CVE-2022-31160 / CWE-79"),

        Lib(name: "AngularJS", marker: "angularjs",
            fileRegexes: [rx("angular(?:js)?[-.]" + ver + "(?:\\.min)?\\.js")],
            contentRegexes: [rx("AngularJS v" + ver)],
            safeMin: [2, 0, 0], safeMinLabel: "any 1.x (migrate off)", severity: .medium,
            issue: "AngularJS 1.x reached end-of-life in Jan 2022 and receives no security fixes. It has a long history of expression-sandbox escapes leading to XSS; the sandbox was removed entirely, so any client-controlled expression is dangerous.",
            reference: "CWE-1104 / CWE-79"),

        Lib(name: "Bootstrap", marker: "bootstrap",
            fileRegexes: [rx("bootstrap[-.]" + ver + "(?:[-.]dist)?(?:\\.min)?\\.js")],
            contentRegexes: [rx("Bootstrap v" + ver)],
            safeMin: [4, 3, 1], safeMinLabel: "4.3.1", severity: .medium,
            issue: "Bootstrap < 4.3.1 (and 3.x) has XSS in data-target/data-template attributes of several components (CVE-2019-8331, CVE-2018-14040/14041/14042).",
            reference: "CVE-2019-8331 / CWE-79"),

        Lib(name: "Lodash", marker: "lodash",
            fileRegexes: [rx("lodash[-.]" + ver)],
            contentRegexes: [rx("lodash[\\s\\S]{0,40}?VERSION\\s*=\\s*[\"']" + ver)],
            safeMin: [4, 17, 21], safeMinLabel: "4.17.21", severity: .medium,
            issue: "Lodash < 4.17.21 is vulnerable to prototype pollution (CVE-2019-10744, CVE-2020-8203) and command/ReDoS issues that can escalate to remote code execution in some sinks.",
            reference: "CVE-2020-8203 / CWE-1321: Prototype Pollution"),

        Lib(name: "Moment.js", marker: "moment.js",
            fileRegexes: [rx("moment[-.]" + ver)],
            contentRegexes: [rx("moment\\.js[\\s\\S]{0,60}?version\\s*:\\s*[\"']?" + ver)],
            safeMin: [2, 29, 4], safeMinLabel: "2.29.4", severity: .low,
            issue: "Moment.js < 2.29.4 has a ReDoS (CVE-2022-31129) and a path-traversal in locale loading (CVE-2022-24785). The library is also in maintenance-only mode.",
            reference: "CVE-2022-31129 / CWE-1333: Inefficient Regular Expression Complexity"),

        Lib(name: "Handlebars", marker: "handlebars",
            fileRegexes: [rx("handlebars[-.]v?" + ver)],
            contentRegexes: [rx("Handlebars[\\s\\S]{0,20}?VERSION\\s*=\\s*[\"']" + ver), rx("Handlebars v" + ver)],
            safeMin: [4, 7, 7], safeMinLabel: "4.7.7", severity: .medium,
            issue: "Handlebars < 4.7.7 has prototype-pollution / arbitrary-code-execution issues when compiling untrusted templates (CVE-2019-19919, CVE-2021-23369, CVE-2021-23383).",
            reference: "CVE-2021-23369 / CWE-1321"),
    ]

    static func scanDocument(url: URL?, text: String) -> [Hit] {
        let urlStr = url?.absoluteString
        var out: [Hit] = []
        var seen = Set<String>()
        let lowerText = text.count > 400_000 ? String(text.prefix(400_000)).lowercased() : text.lowercased()

        for lib in libs {
            var found: String?

            if let urlStr, let v = firstCapture(lib.fileRegexes, in: urlStr) {
                found = v
            } else if lowerText.contains(lib.marker) {
                found = firstCapture(lib.contentRegexes, in: text)
            }
            guard let vLabel = found else { continue }
            let parsed = parseVersion(vLabel)
            guard !parsed.isEmpty, versionLess(parsed, than: lib.safeMin),
                  seen.insert(lib.name).inserted else { continue }
            out.append(Hit(name: lib.name, version: parsed, versionLabel: vLabel,
                           safeMinLabel: lib.safeMinLabel, severity: lib.severity,
                           issue: lib.issue, reference: lib.reference,
                           source: url?.absoluteString ?? "inline script"))
        }
        return out
    }

    static func makeFindings(_ hits: [Hit]) -> [Finding] {
        guard !hits.isEmpty else { return [] }
        var byName: [String: [Hit]] = [:]
        for h in hits { byName[h.name, default: []].append(h) }

        var out: [Finding] = []
        for (name, group) in byName {
            let worst = group.min { versionLess($0.version, than: $1.version) }!
            let sources = Array(Set(group.map { $0.source })).sorted()
            out.append(Finding(
                title: "Outdated JavaScript library: \(name) \(worst.versionLabel)",
                severity: worst.severity,
                category: "Vulnerable Component",
                location: sources.first ?? "JavaScript",
                detail: "The site loads \(name) \(worst.versionLabel). \(worst.issue)",
                evidence: "Detected version: \(worst.versionLabel) (safe: \(worst.safeMinLabel)+)\nSource(s): \(sources.prefix(3).joined(separator: ", "))\(sources.count > 3 ? " ..." : "")",
                exploit: "Attackers scan for outdated libraries and fire the matching public exploit. A vulnerable client-side dependency lets them run script in your users' browsers (XSS), pollute object prototypes, or trigger denial-of-service, with no work of their own.",
                remediation: "Upgrade \(name) to \(worst.safeMinLabel) or later and keep dependencies patched (e.g. Dependabot / `npm audit`). Remove libraries you no longer use.",
                reference: worst.reference))
        }
        return out.sorted { $0.severity < $1.severity }
    }

    private static func firstCapture(_ regexes: [NSRegularExpression], in text: String) -> String? {
        let ns = text as NSString
        let range = NSRange(location: 0, length: ns.length)
        for re in regexes {
            if let m = re.firstMatch(in: text, range: range), m.numberOfRanges > 1 {
                return ns.substring(with: m.range(at: 1))
            }
        }
        return nil
    }

    private static func parseVersion(_ s: String) -> [Int] {
        s.split(separator: ".").prefix(4).compactMap { comp -> Int? in
            let digits = comp.prefix { $0.isNumber }
            return digits.isEmpty ? nil : Int(digits)
        }
    }

    private static func versionLess(_ a: [Int], than b: [Int]) -> Bool {
        let n = Swift.max(a.count, b.count)
        for i in 0..<n {
            let x = i < a.count ? a[i] : 0
            let y = i < b.count ? b[i] : 0
            if x != y { return x < y }
        }
        return false
    }
}
