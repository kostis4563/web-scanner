import SwiftUI
import AppKit

enum DS {

    enum C {
        static let bg           = Color(hex: 0x050506)
        static let rail         = Color(hex: 0x09090B)
        static let surface      = Color(hex: 0x101014)
        static let surfaceElev  = Color(hex: 0x15151B)
        static let hover        = Color(hex: 0x1C1C23)
        static let border       = Color(hex: 0x24242C)
        static let borderStrong = Color(hex: 0x393944)
        static let grid         = Color(hex: 0x17171D)

        static let text         = Color(hex: 0xF6F6F7)
        static let textBody     = Color(hex: 0xC1C1C7)
        static let textDim      = Color(hex: 0x85858F)
        static let textFaint    = Color(hex: 0x5B5B64)

        static let accent       = Color(hex: 0x98A7F5)
        static let accentBright = Color(hex: 0xBCC5FF)
        static let accentDeep   = Color(hex: 0x7383D1)
        static let onAccent     = Color(hex: 0x090A10)

        static let critical     = Color(hex: 0xF0737A)
        static let high         = Color(hex: 0xE89B68)
        static let medium       = Color(hex: 0xD4B76D)
        static let low          = Color(hex: 0x78A7C2)
        static let info         = Color(hex: 0x8D8E98)
        static let success      = Color(hex: 0x7EB68B)
        static let warn         = Color(hex: 0xD9A16E)
        static let poc          = Color(hex: 0xAFA0CB)
    }

    enum S {
        static let xxs: CGFloat = 4
        static let xs: CGFloat  = 8
        static let sm: CGFloat  = 12
        static let md: CGFloat  = 16
        static let lg: CGFloat  = 24
        static let xl: CGFloat  = 32
        static let xxl: CGFloat = 48
    }

    enum R {
        static let xs: CGFloat  = 5
        static let sm: CGFloat  = 9
        static let md: CGFloat  = 13
        static let lg: CGFloat  = 18
        static let pill: CGFloat = 9999
    }

    static func font(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        Font.custom("Helvetica Neue", size: size).weight(weight)
    }
    static func mono(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .monospaced)
    }
}

extension Color {
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red:   Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue:  Double(hex & 0xFF) / 255,
            opacity: 1
        )
    }
}

struct DSLabel: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text)
            .font(DS.font(11, .medium))
            .foregroundStyle(DS.C.textDim)
    }
}

struct DSCard<Content: View>: View {
    var padding: CGFloat = DS.S.md
    var radius: CGFloat = DS.R.lg
    @ViewBuilder var content: Content
    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(DS.C.surfaceElev.opacity(0.82))
            .clipShape(RoundedRectangle(cornerRadius: radius, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .strokeBorder(Color.white.opacity(0.07), lineWidth: 1)
            )
    }
}

struct DSPrimaryButtonStyle: ButtonStyle {
    var enabled: Bool = true
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(DS.font(13, .semibold))
            .foregroundStyle(enabled ? DS.C.bg : DS.C.textDim)
            .padding(.vertical, 10)
            .padding(.horizontal, DS.S.lg)
            .background(
                enabled
                ? (configuration.isPressed ? DS.C.textBody : DS.C.text)
                : DS.C.surfaceElev
            )
            .clipShape(RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous)
                    .strokeBorder(enabled ? Color.clear : DS.C.border, lineWidth: 1)
            )
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .contentShape(RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous))
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

struct DSSecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(DS.font(12, .medium))
            .foregroundStyle(DS.C.textBody)
            .padding(.vertical, 8)
            .padding(.horizontal, DS.S.md)
            .background(configuration.isPressed ? DS.C.hover : DS.C.surface)
            .clipShape(RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous)
                .strokeBorder(Color.white.opacity(0.09), lineWidth: 1))
            .scaleEffect(configuration.isPressed ? 0.985 : 1)
            .contentShape(RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous))
    }
}

struct DSCancelButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(DS.font(12.5, .semibold))
            .foregroundStyle(configuration.isPressed ? DS.C.text : DS.C.critical)
            .padding(.vertical, 10)
            .padding(.horizontal, DS.S.md)
            .background(configuration.isPressed ? DS.C.critical.opacity(0.16) : DS.C.surface)
            .clipShape(RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous)
                    .strokeBorder(DS.C.critical.opacity(0.28), lineWidth: 1)
            )
            .scaleEffect(configuration.isPressed ? 0.98 : 1)
            .contentShape(RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous))
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

struct DSChip: View {
    let text: String
    var tint: Color = DS.C.textDim
    var body: some View {
        Text(text.uppercased())
            .font(DS.font(9.5, .semibold))
            .padding(.horizontal, DS.S.xs)
            .padding(.vertical, 3)
            .background(tint.opacity(0.16))
            .foregroundStyle(tint)
            .clipShape(RoundedRectangle(cornerRadius: DS.R.xs, style: .continuous))
    }
}

private struct DarkField: ViewModifier {
    func body(content: Content) -> some View {
        content
            .textFieldStyle(.plain)
            .foregroundStyle(DS.C.text)
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(DS.C.surface)
            .clipShape(RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous)
                    .strokeBorder(DS.C.border, lineWidth: 1)
            )
    }
}

extension View {
    func darkField() -> some View { modifier(DarkField()) }

    func darkEditor(height: CGFloat) -> some View {
        self
            .font(DS.mono(11))
            .foregroundStyle(DS.C.text)
            .scrollContentBackground(.hidden)
            .frame(height: height)
            .padding(6)
            .background(DS.C.surface)
            .clipShape(RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: DS.R.sm, style: .continuous)
                    .strokeBorder(DS.C.border, lineWidth: 1)
            )
    }
}
