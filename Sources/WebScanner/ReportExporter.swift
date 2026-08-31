import Foundation

enum ReportExporter {

    static func markdown(_ report: ScanReport) -> String {
        let df = DateFormatter()
        df.dateStyle = .medium
        df.timeStyle = .medium

        var out = ""
        out += "# Web Security Scan Report\n\n"
        out += "- **Target:** \(report.target)\n"
        out += "- **Scanned URL:** \(report.finalURL)\n"
        out += "- **Started:** \(df.string(from: report.startedAt))\n"
        out += "- **Finished:** \(df.string(from: report.finishedAt))\n"
        out += "- **Overall grade:** \(report.grade)\n\n"

        let c = report.counts
        out += "## Summary\n\n"
        out += "| Severity | Count |\n| --- | --- |\n"
        for sev in Severity.allCases {
            out += "| \(sev.label) | \(c[sev] ?? 0) |\n"
        }
        out += "\n> ⚠️ For authorized security testing only. Verify findings before acting.\n\n"

        out += "## Findings\n\n"
        if report.findings.isEmpty {
            out += "_No findings._\n"
        }
        for (i, f) in report.findings.enumerated() {
            out += "### \(i + 1). [\(f.severity.label)] \(f.title)\n\n"
            out += "- **Category:** \(f.category)\n"
            out += "- **Location:** \(f.location)\n"
            if let ref = f.reference { out += "- **Reference:** \(ref)\n" }
            out += "\n**What it is:** \(f.detail)\n\n"
            out += "**Evidence:**\n\n```\n\(f.evidence)\n```\n\n"
            if let content = f.capturedContent, !content.isEmpty {

                let fence = content.contains("```") ? "````" : "```"
                out += "<details><summary><strong>File contents</strong> "
                out += "(\(content.components(separatedBy: "\n").count) lines)</summary>\n\n"
                out += "\(fence)\n\(content)\n\(fence)\n\n</details>\n\n"
            }
            let perf = f.category == "Performance"
            out += "**\(perf ? "Impact on users" : "How it could be exploited"):** \(f.exploit)\n\n"
            if let repro = f.reproduction, !repro.isEmpty {
                out += "**Proof of concept (run in terminal):**\n\n```sh\n\(repro)\n```\n\n"
            }
            out += "**\(perf ? "How to make it faster" : "How to fix it"):** \(f.remediation)\n\n"
            out += "---\n\n"
        }
        return out
    }

    static func json(_ report: ScanReport) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(report),
              let s = String(data: data, encoding: .utf8) else {
            return "{\"error\":\"failed to encode report\"}"
        }
        return s
    }
}
