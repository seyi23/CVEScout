import Foundation

/// User interface language. CVEScout ships German and English; every other system language falls back to English.
///
/// Resolution order: `--lang de|en` argument → `CVESCOUT_LANG` environment variable →
/// app setting (`appLanguage` in UserDefaults) → first preferred system language.
/// The value is fixed for the lifetime of the process (changing it in the app needs a restart).
public enum Language: String, Sendable, CaseIterable {
    case de, en

    public static let current: Language = detect(
        arguments: CommandLine.arguments,
        environment: ProcessInfo.processInfo.environment,
        setting: UserDefaults.standard.string(forKey: "appLanguage"),
        preferred: Locale.preferredLanguages
    )

    static func detect(arguments: [String], environment: [String: String], setting: String?, preferred: [String]) -> Language {
        if let i = arguments.firstIndex(of: "--lang"), i + 1 < arguments.count,
           let lang = parse(arguments[i + 1]) { return lang }
        if let lang = environment["CVESCOUT_LANG"].flatMap(parse) { return lang }
        if let lang = setting.flatMap(parse) { return lang }
        return preferred.first.flatMap(parse) ?? .en
    }

    /// "de", "de-DE", "de_AT" → .de; "en…" → .en; anything else → nil.
    static func parse(_ code: String) -> Language? {
        let lower = code.lowercased()
        if lower.hasPrefix("de") { return .de }
        if lower.hasPrefix("en") { return .en }
        return nil
    }

    public var locale: Locale { Locale(identifier: rawValue) }
}

/// Picks the German or English text for the current language.
@inline(__always)
public func tr(_ de: String, _ en: String) -> String {
    Language.current == .de ? de : en
}
