import Foundation

enum URLTemplate {

    static let domainAlphabet = Array("abcdefghijklmnopqrstuvwxyz0123456789-_").map(String.init)

    static func isTemplate(_ s: String) -> Bool {
        s.contains(where: { "?*[](){}$".contains($0) })
    }

    static func expand(_ template: String, dictionary: [String] = [],
                       maxLength: Int = 44, limit: Int = 5000) -> [String] {
        let segments = parse(template, dictionary: dictionary, maxLength: maxLength, cap: limit)
        return product(of: segments, limit: limit)
    }

    private static func parse(_ template: String, dictionary: [String],
                              maxLength: Int, cap: Int) -> [[String]] {
        var segments: [[String]] = []
        var literal = ""
        let chars = Array(template)
        var i = 0

        func flushLiteral() {
            if !literal.isEmpty { segments.append([literal]); literal = "" }
        }

        let baseLength = chars.filter { $0 != "*" }.count

        while i < chars.count {
            let c = chars[i]
            switch c {
            case "(":
                if let close = matchingIndex(of: ")", in: chars, from: i + 1) {
                    let inner = String(chars[(i + 1)..<close])
                    let base = inner.components(separatedBy: ",")
                    i = close + 1
                    let q = readQuantifier(chars, from: i)
                    i += q.consumed
                    flushLiteral()
                    segments.append(applyQuantifier(base: base, q: q, cap: cap))
                } else { literal.append(c); i += 1 }

            case "[":
                if let close = matchingIndex(of: "]", in: chars, from: i + 1) {
                    let inner = String(chars[(i + 1)..<close])
                    let set = parseCharset(inner)
                    i = close + 1
                    let q = readQuantifier(chars, from: i)
                    i += q.consumed
                    flushLiteral()
                    segments.append(applyQuantifier(base: set, q: q, cap: cap))
                } else { literal.append(c); i += 1 }

            case "?":
                flushLiteral()
                segments.append(domainAlphabet)
                i += 1

            case "*":
                flushLiteral()
                let delta = max(1, min(maxLength - baseLength, 3))
                segments.append(repeated(base: domainAlphabet, min: 1, max: delta, cap: cap))
                i += 1

            case "$":
                flushLiteral()
                segments.append(dictionary.isEmpty ? [""] : dictionary)
                i += 1

            default:
                literal.append(c)
                i += 1
            }
        }
        flushLiteral()
        return segments
    }

    private struct Quantifier { var min: Int?; var max: Int?; var optional: Bool; var consumed: Int }

    private static func readQuantifier(_ chars: [Character], from i: Int) -> Quantifier {
        guard i < chars.count else { return Quantifier(min: nil, max: nil, optional: false, consumed: 0) }
        if chars[i] == "?" {
            return Quantifier(min: nil, max: nil, optional: true, consumed: 1)
        }
        if chars[i] == "{", let close = matchingIndex(of: "}", in: chars, from: i + 1) {
            let body = String(chars[(i + 1)..<close])
            let parts = body.components(separatedBy: ",")
            let consumed = close - i + 1
            if parts.count == 2, let lo = Int(parts[0].trimmingCharacters(in: .whitespaces)),
               let hi = Int(parts[1].trimmingCharacters(in: .whitespaces)) {
                return Quantifier(min: lo, max: hi, optional: false, consumed: consumed)
            }
            if parts.count == 1, let n = Int(parts[0].trimmingCharacters(in: .whitespaces)) {
                return Quantifier(min: n, max: n, optional: false, consumed: consumed)
            }
            return Quantifier(min: nil, max: nil, optional: false, consumed: consumed)
        }
        return Quantifier(min: nil, max: nil, optional: false, consumed: 0)
    }

    private static func applyQuantifier(base: [String], q: Quantifier, cap: Int) -> [String] {
        var set: [String]
        if let lo = q.min, let hi = q.max {
            set = repeated(base: base, min: lo, max: hi, cap: cap)
        } else {
            set = base
        }
        if q.optional { set.append("") }
        return dedupe(set, cap: cap)
    }

    private static func parseCharset(_ inner: String) -> [String] {
        let forbidden = Set("?[](){}!*$")
        let a = Array(inner)
        var out: [String] = []
        var seen = Set<Character>()
        var i = 0
        while i < a.count {
            if i + 2 < a.count, a[i + 1] == "-" {
                let lo = a[i].unicodeScalars.first!.value
                let hi = a[i + 2].unicodeScalars.first!.value
                if lo <= hi {
                    for v in lo...hi {
                        if let sc = Unicode.Scalar(v) {
                            let ch = Character(sc)
                            if !forbidden.contains(ch), seen.insert(ch).inserted { out.append(String(ch)) }
                        }
                    }
                }
                i += 3
            } else {
                let ch = a[i]
                if !forbidden.contains(ch), seen.insert(ch).inserted { out.append(String(ch)) }
                i += 1
            }
        }
        return out
    }

    private static func repeated(base: [String], min lo: Int, max hi: Int, cap: Int) -> [String] {
        guard !base.isEmpty, hi >= 1, lo <= hi else { return lo <= 0 ? [""] : [] }
        var out: [String] = []
        if lo <= 0 { out.append("") }
        var current: [String] = [""]
        for len in 1...hi {
            var next: [String] = []
            outer: for prefix in current {
                for b in base {
                    next.append(prefix + b)
                    if next.count >= cap { break outer }
                }
            }
            current = next
            if len >= lo { out.append(contentsOf: current) }
            if out.count >= cap { break }
        }
        return Array(out.prefix(cap))
    }

    private static func product(of segments: [[String]], limit: Int) -> [String] {
        guard !segments.isEmpty else { return [] }
        var results: [String] = [""]
        for seg in segments {
            let options = seg.isEmpty ? [""] : seg
            var next: [String] = []
            outer: for prefix in results {
                for s in options {
                    next.append(prefix + s)
                    if next.count >= limit { break outer }
                }
            }
            results = next
        }
        return results
    }

    private static func matchingIndex(of ch: Character, in chars: [Character], from start: Int) -> Int? {
        var i = start
        while i < chars.count {
            if chars[i] == ch { return i }
            i += 1
        }
        return nil
    }

    private static func dedupe(_ items: [String], cap: Int) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for it in items where seen.insert(it).inserted {
            out.append(it)
            if out.count >= cap { break }
        }
        return out
    }
}
