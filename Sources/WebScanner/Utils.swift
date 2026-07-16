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

func snippet(_ text: String, max: Int = 200) -> String {
    let collapsed = text
        .replacingOccurrences(of: "\n", with: " ")
        .replacingOccurrences(of: "\t", with: " ")
    let trimmed = collapsed.trimmingCharacters(in: .whitespaces)
    if trimmed.count <= max { return trimmed }
    return String(trimmed.prefix(max)) + "..."
}
