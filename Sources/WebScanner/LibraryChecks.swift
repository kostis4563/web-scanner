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

        Lib(name: "DOMPurify", marker: "dompurify",
            fileRegexes: [rx("\\bdompurify[-.]v?" + ver), rx("\\bpurify[-.]v?" + ver)],
            contentRegexes: [rx("DOMPurify[\\s\\S]{0,40}?VERSION\\s*[:=]\\s*[\"']" + ver), rx("dompurify[\\s\\S]{0,30}?[\"']" + ver + "[\"']")],
            safeMin: [3, 0, 9], safeMinLabel: "3.0.9", severity: .high,
            issue: "DOMPurify < 3.0.9 has multiple mutation-XSS sanitizer-bypass flaws (e.g. CVE-2024-45801, CVE-2020-26870) that let crafted markup survive sanitization and execute script - defeating the exact protection it is deployed for.",
            reference: "CVE-2024-45801 / CWE-79"),

        Lib(name: "Axios", marker: "axios",
            fileRegexes: [rx("\\baxios[-.@/]v?" + ver)],
            contentRegexes: [rx("axios[\\s\\S]{0,40}?VERSION\\s*[:=]\\s*[\"']" + ver)],
            safeMin: [1, 6, 0], safeMinLabel: "1.6.0", severity: .medium,
            issue: "Axios < 1.6.0 leaks the XSRF-TOKEN cookie to third-party hosts on cross-origin requests (CVE-2023-45857); 0.x releases also have SSRF and ReDoS issues (CVE-2020-28168, CVE-2021-3749).",
            reference: "CVE-2023-45857 / CWE-918"),

        Lib(name: "Underscore.js", marker: "underscore",
            fileRegexes: [rx("\\bunderscore[-.]v?" + ver)],
            contentRegexes: [rx("underscore[\\s\\S]{0,40}?VERSION\\s*=\\s*[\"']" + ver)],
            safeMin: [1, 12, 1], safeMinLabel: "1.12.1", severity: .high,
            issue: "Underscore 1.3.2–1.12.0 allows arbitrary code execution via _.template when a template setting is attacker-influenced (CVE-2021-23358).",
            reference: "CVE-2021-23358 / CWE-94"),

        Lib(name: "Marked", marker: "marked",
            fileRegexes: [rx("\\bmarked[-.]v?" + ver)],
            contentRegexes: [rx("marked[\\s\\S]{0,30}?version\\s*[:=]\\s*[\"']?v?" + ver)],
            safeMin: [4, 0, 10], safeMinLabel: "4.0.10", severity: .medium,
            issue: "Marked < 4.0.10 has regular-expression denial-of-service flaws (CVE-2022-21680, CVE-2022-21681) that let untrusted markdown hang the parser.",
            reference: "CVE-2022-21681 / CWE-1333"),

        Lib(name: "Prism.js", marker: "prism",
            fileRegexes: [rx("\\bprism[-.]v?" + ver)],
            contentRegexes: [rx("Prism[\\s\\S]{0,30}?version\\s*[:=]\\s*[\"']?" + ver)],
            safeMin: [1, 27, 0], safeMinLabel: "1.27.0", severity: .medium,
            issue: "PrismJS < 1.27.0 is vulnerable to DOM-clobbering-based XSS (CVE-2022-23647) when highlighting attacker-influenced content.",
            reference: "CVE-2022-23647 / CWE-79"),

        Lib(name: "Select2", marker: "select2",
            fileRegexes: [rx("\\bselect2[-.@/]v?" + ver)],
            contentRegexes: [rx("Select2[\\s\\S]{0,30}?[\"']" + ver + "[\"']")],
            safeMin: [4, 0, 6], safeMinLabel: "4.0.6", severity: .medium,
            issue: "Select2 < 4.0.6 is vulnerable to cross-site scripting through unescaped option/result rendering.",
            reference: "CWE-79: Cross-Site Scripting"),

        Lib(name: "Video.js", marker: "video.js",
            fileRegexes: [rx("\\bvideo[-.]?js[-.@/]v?" + ver), rx("\\bvideojs[-.@/]v?" + ver)],
            contentRegexes: [rx("video\\.js[\\s\\S]{0,30}?" + ver), rx("VERSION\\s*=\\s*[\"']" + ver + "[\"'][\\s\\S]{0,30}?video")],
            safeMin: [7, 14, 3], safeMinLabel: "7.14.3", severity: .medium,
            issue: "Video.js < 7.14.3 has a cross-site scripting flaw in the track/subtitle handling (CVE-2021-23414).",
            reference: "CVE-2021-23414 / CWE-79"),

        Lib(name: "jQuery Validation", marker: "jquery.validate",
            fileRegexes: [rx("jquery[.-]validate(?:\\.min)?[.-]v?" + ver)],
            contentRegexes: [rx("jQuery Validation Plugin[\\s\\S]{0,30}?v?" + ver)],
            safeMin: [1, 19, 5], safeMinLabel: "1.19.5", severity: .medium,
            issue: "jQuery Validation < 1.19.5 has a regular-expression denial-of-service flaw (CVE-2022-31147) in its URL/e-mail validators.",
            reference: "CVE-2022-31147 / CWE-1333"),

        Lib(name: "Chart.js", marker: "chart.js",
            fileRegexes: [rx("chart\\.js[/@-]v?" + ver), rx("chart(?:\\.min)?\\.js[?&]ver=" + ver)],
            contentRegexes: [rx("Chart\\.js v" + ver)],
            safeMin: [2, 9, 4], safeMinLabel: "2.9.4", severity: .medium,
            issue: "Chart.js < 2.9.4 is vulnerable to prototype pollution via crafted chart options (CVE-2020-7746), which can corrupt Object.prototype and lead to denial-of-service or downstream code execution.",
            reference: "CVE-2020-7746 / CWE-1321: Prototype Pollution"),

        Lib(name: "SheetJS (xlsx)", marker: "xlsx",
            fileRegexes: [rx("xlsx[-@/]v?" + ver), rx("xlsx(?:\\.full|\\.core)?(?:\\.min)?\\.js[?&]ver=" + ver)],
            contentRegexes: [rx("XLSX\\.version\\s*=\\s*[\"']" + ver)],
            safeMin: [0, 20, 2], safeMinLabel: "0.20.2", severity: .high,
            issue: "SheetJS xlsx < 0.20.2 is affected by prototype pollution when parsing crafted spreadsheets (CVE-2023-30533, fixed 0.19.3) and a regular-expression denial-of-service (CVE-2024-22363, fixed 0.20.2).",
            reference: "CVE-2023-30533 / CWE-1321: Prototype Pollution"),

        Lib(name: "pdf.js", marker: "pdfjs",
            fileRegexes: [rx("pdf(?:js)?\\.js[/@]v?" + ver), rx("pdfjs-dist[@/]v?" + ver)],
            contentRegexes: [rx("pdfjsVersion\\s*=\\s*[\"']" + ver), rx("(?:PDFJS\\.version|apiVersion)\\s*[:=]\\s*[\"']" + ver)],
            safeMin: [4, 2, 67], safeMinLabel: "4.2.67", severity: .high,
            issue: "Mozilla pdf.js before 4.2.67 lets a crafted PDF execute arbitrary JavaScript in the page when the built-in viewer renders it (CVE-2024-4367), because font handling does not restrict evaluated expressions.",
            reference: "CVE-2024-4367 / CWE-94: Code Injection"),

        Lib(name: "highlight.js", marker: "hljs",
            fileRegexes: [rx("highlight\\.js[/@]v?" + ver), rx("highlightjs[/@-]v?" + ver)],
            contentRegexes: [rx("hljs[\\s\\S]{0,30}?versionString\\s*[:=]\\s*[\"']" + ver), rx("highlight\\.js\\s+v?" + ver)],
            safeMin: [10, 4, 1], safeMinLabel: "10.4.1 (9.18.5 on the 9.x line)", severity: .medium,
            issue: "highlight.js before 10.4.1 (and 9.x before 9.18.5) is vulnerable to prototype pollution via crafted language grammar/config (CVE-2020-26237), allowing an attacker to poison Object.prototype.",
            reference: "CVE-2020-26237 / CWE-1321: Prototype Pollution"),

        Lib(name: "UAParser.js", marker: "uaparser",
            fileRegexes: [rx("ua-parser(?:-js)?[@/-]v?" + ver), rx("uaparser(?:\\.js)?[/@-]v?" + ver)],
            contentRegexes: [rx("LIBVERSION\\s*=\\s*[\"']" + ver)],
            safeMin: [1, 0, 33], safeMinLabel: "1.0.33 (0.7.33 on the 0.7.x line)", severity: .medium,
            issue: "ua-parser-js before 1.0.33 (and 0.7.x before 0.7.33) has a regular-expression denial-of-service in its User-Agent parsing (CVE-2022-25927); versions 0.7.29/0.8.0/1.0.0 were also briefly trojanised in the 2021 npm account compromise.",
            reference: "CVE-2022-25927 / CWE-1333: Inefficient Regular Expression Complexity"),

        Lib(name: "Quill", marker: "quill",
            fileRegexes: [rx("quill[.-]v?" + ver), rx("quill(?:\\.min)?\\.js[?&]ver=" + ver)],
            contentRegexes: [rx("Quill[\\s\\S]{0,40}?version\\s*[:=]\\s*[\"']" + ver)],
            safeMin: [2, 0, 0], safeMinLabel: "2.0.0", severity: .medium,
            issue: "Quill 1.x is affected by cross-site scripting through crafted clipboard/formula content (CVE-2021-3163) and receives no further 1.x security fixes; upgrade to the 2.x line.",
            reference: "CVE-2021-3163 / CWE-79: Cross-Site Scripting"),

        Lib(name: "CKEditor 4", marker: "ckeditor",
            fileRegexes: [rx("ckeditor4?[/@-]v?" + ver)],
            contentRegexes: [rx("version\\s*:\\s*[\"']" + ver + "[\"']\\s*,\\s*revision"), rx("CKEDITOR\\.version\\s*=\\s*[\"']" + ver)],
            safeMin: [4, 21, 0], safeMinLabel: "4.21.0", severity: .medium,
            issue: "CKEditor 4 before 4.21.0 has cross-site scripting flaws in the Iframe Dialog and Media Embed plugins (CVE-2023-28439) and, in older builds, the HTML data processor (CVE-2021-33829, CVE-2022-24728).",
            reference: "CVE-2023-28439 / CWE-79: Cross-Site Scripting"),

        Lib(name: "TinyMCE", marker: "tinymce",
            fileRegexes: [rx("tinymce[/@-]v?" + ver)],
            contentRegexes: [rx("tinymce[\\s\\S]{0,60}?[\"']version[\"']\\s*[:=]\\s*[\"']" + ver)],
            safeMin: [6, 7, 0], safeMinLabel: "6.7.0 (5.x is end-of-life)", severity: .medium,
            issue: "TinyMCE before 6.7.0 is vulnerable to mutation cross-site scripting via crafted content (CVE-2023-45818, also fixed in 5.10.9); the entire 5.x line is end-of-life and no longer patched.",
            reference: "CVE-2023-45818 / CWE-79: Cross-Site Scripting"),

        Lib(name: "DataTables", marker: "datatables",
            fileRegexes: [rx("datatables\\.net[/@]v?" + ver), rx("(?:jquery\\.)?datatables[.-]v?" + ver)],
            contentRegexes: [rx("dataTable\\.version\\s*=\\s*[\"']" + ver)],
            safeMin: [1, 11, 3], safeMinLabel: "1.11.3", severity: .medium,
            issue: "jQuery DataTables before 1.11.3 has a cross-site scripting flaw in cell rendering (CVE-2021-23445) and, before 1.10.23, prototype pollution in its options handling (CVE-2020-28458).",
            reference: "CVE-2021-23445 / CWE-79: Cross-Site Scripting"),

        Lib(name: "crypto-js", marker: "cryptojs",
            fileRegexes: [rx("crypto-js[/@-]v?" + ver)],
            contentRegexes: [rx("crypto-js[\\s\\S]{0,40}?version\\s*[:=]\\s*[\"']" + ver)],
            safeMin: [4, 2, 0], safeMinLabel: "4.2.0", severity: .medium,
            issue: "crypto-js before 4.2.0 derives keys with PBKDF2 defaulting to a single SHA-1 iteration (CVE-2023-46233), producing weak, brute-forceable keys from passwords.",
            reference: "CVE-2023-46233 / CWE-916: Use of Password Hash With Insufficient Computational Effort"),

        Lib(name: "node-forge", marker: "forge",
            fileRegexes: [rx("node-forge[/@-]v?" + ver), rx("forge/v?" + ver + "/")],
            contentRegexes: [rx("forge\\.version\\s*=\\s*[\"']" + ver)],
            safeMin: [1, 3, 0], safeMinLabel: "1.3.0", severity: .high,
            issue: "node-forge before 1.3.0 has RSA PKCS#1 v1.5 signature-verification bypass flaws (CVE-2022-24771, CVE-2022-24772, CVE-2022-24773) that let an attacker forge signatures accepted by the library.",
            reference: "CVE-2022-24771 / CWE-347: Improper Verification of Cryptographic Signature"),

        Lib(name: "jQuery Mobile", marker: "jquery mobile",
            fileRegexes: [rx("jquery\\.mobile[-.]v?" + ver), rx("jquerymobile[/@-]v?" + ver)],
            contentRegexes: [rx("jQuery Mobile[\\s\\S]{0,20}?v?" + ver)],
            safeMin: [2, 0, 0], safeMinLabel: "1.x is end-of-life (migrate off)", severity: .medium,
            issue: "jQuery Mobile is an abandoned project (last release 1.4.5) with a known, unpatched DOM cross-site scripting issue driven by location.hash; it receives no security fixes and should be removed.",
            reference: "CWE-79 / CWE-1104: Use of Unmaintained Third-Party Components"),

        Lib(name: "Vue 2", marker: "vue",
            fileRegexes: [rx("\\bvue[@/]v?" + ver), rx("\\bvue(?:\\.min|\\.runtime)?\\.js[?&]ver=" + ver)],
            contentRegexes: [rx("Vue\\.version\\s*=\\s*[\"']" + ver)],
            safeMin: [3, 0, 0], safeMinLabel: "3.x (Vue 2 is end-of-life)", severity: .medium,
            issue: "Vue 2.x reached end-of-life on 31 Dec 2023 and no longer receives security patches; migrate to Vue 3, which is actively maintained.",
            reference: "CWE-1104: Use of Unmaintained Third-Party Components"),

        Lib(name: "Dojo Toolkit", marker: "dojo",
            fileRegexes: [rx("dojo[/@-]v?" + ver)],
            contentRegexes: [rx("dojo[\\s\\S]{0,40}?version[\\s\\S]{0,20}?[\"']" + ver + "[\"']")],
            safeMin: [1, 17, 3], safeMinLabel: "1.17.3", severity: .medium,
            issue: "Dojo Toolkit before 1.17.3 is vulnerable to prototype pollution via its object-manipulation utilities (CVE-2021-23450), allowing an attacker to poison Object.prototype.",
            reference: "CVE-2021-23450 / CWE-1321: Prototype Pollution"),
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
