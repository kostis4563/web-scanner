import Foundation

extension Array {

    func chunked(into size: Int) -> [[Element]] {
        guard size > 0 else { return [self] }
        var result: [[Element]] = []
        var i = 0
        while i < count {
            result.append(Array(self[i..<Swift.min(i + size, count)]))
            i += size
        }
        return result
    }
}

func regexMatches(_ pattern: String, in text: String) -> Bool {
    guard let re = try? NSRegularExpression(pattern: pattern, options: []) else { return false }
    let range = NSRange(text.startIndex..<text.endIndex, in: text)
    return re.firstMatch(in: text, options: [], range: range) != nil
}

func redact(_ secret: String) -> String {
    let s = secret.trimmingCharacters(in: .whitespacesAndNewlines)
    guard s.count > 12 else { return String(repeating: "•", count: max(s.count, 4)) }
    let head = s.prefix(4)
    let tail = s.suffix(4)
    return "\(head)...\(tail)  (\(s.count) chars)"
}

func capturedBody(_ text: String, limit: Int = 200_000) -> String? {
    let normalized = text
        .replacingOccurrences(of: "\r\n", with: "\n")
        .replacingOccurrences(of: "\r", with: "\n")
    let trimmed = normalized.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }

    if trimmed.unicodeScalars.prefix(4096).contains(where: { $0.value == 0 }) { return nil }

    guard trimmed.count > limit else { return trimmed }
    return String(trimmed.prefix(limit))
        + "\n\n...[truncated - \(trimmed.count) characters total, use the curl command above for the rest]"
}

func recoveredEnvLines(_ text: String, limit: Int = 400) -> String? {
    var runs: [String] = []
    var current = ""
    for scalar in text.unicodeScalars {
        let isPrintable = (scalar.value >= 32 && scalar.value < 127) || scalar.value > 160
        if isPrintable {
            current.unicodeScalars.append(scalar)
        } else {
            if current.count >= 6 { runs.append(current) }
            current = ""
        }
    }
    if current.count >= 6 { runs.append(current) }

    var seen = Set<String>()
    let lines = runs
        .map { $0.trimmingCharacters(in: .whitespaces) }
        .filter { regexMatches("^[A-Za-z_][A-Za-z0-9_]*\\s*=", in: $0) }
        .filter { seen.insert($0).inserted }
        .prefix(limit)

    guard !lines.isEmpty else { return nil }
    return "Recovered from the swap buffer (`vim -r` gives the exact file):\n\n"
        + lines.joined(separator: "\n")
}

func snippet(_ text: String, max: Int = 200) -> String {
    let collapsed = text
        .replacingOccurrences(of: "\n", with: " ")
        .replacingOccurrences(of: "\t", with: " ")
    let trimmed = collapsed.trimmingCharacters(in: .whitespaces)
    if trimmed.count <= max { return trimmed }
    return String(trimmed.prefix(max)) + "..."
}
