import Foundation

/// Lenient dotted numeric version ("142.0.7444.175", "2026.3", "3.4.0_1", "6.4.0 (12345)").
///
/// Leading non-digits are skipped; parsing stops at the first character that is
/// neither a digit nor a dot, so suffixes like build numbers or "esr" are ignored.
public struct Version: Comparable, Hashable, Sendable, CustomStringConvertible {
    public let components: [Int]

    public init(components: [Int]) {
        self.components = components
    }

    public init?(_ string: String) {
        var comps: [Int] = []
        var current = ""
        var started = false
        for ch in string {
            if ch.isASCII, ch.isNumber {
                current.append(ch)
                started = true
            } else if ch == ".", started {
                guard !current.isEmpty else { break }
                comps.append(Int(current.prefix(18)) ?? 0)
                current = ""
            } else if started {
                break
            }
        }
        if !current.isEmpty { comps.append(Int(current.prefix(18)) ?? 0) }
        guard !comps.isEmpty else { return nil }
        self.components = comps
    }

    public var description: String { components.map(String.init).joined(separator: ".") }

    public static func < (lhs: Version, rhs: Version) -> Bool {
        let n = max(lhs.components.count, rhs.components.count)
        for i in 0..<n {
            let l = i < lhs.components.count ? lhs.components[i] : 0
            let r = i < rhs.components.count ? rhs.components[i] : 0
            if l != r { return l < r }
        }
        return false
    }

    public static func == (lhs: Version, rhs: Version) -> Bool {
        !(lhs < rhs) && !(rhs < lhs)
    }

    public func hash(into hasher: inout Hasher) {
        var trimmed = components
        while trimmed.count > 1, trimmed.last == 0 { trimmed.removeLast() }
        hasher.combine(trimmed)
    }

    /// Number of leading components that are identical ("15.8.1" vs "15.8.2" → 2).
    public func commonPrefixLength(with other: Version) -> Int {
        var n = 0
        for (a, b) in zip(components, other.components) {
            guard a == b else { break }
            n += 1
        }
        return n
    }
}

/// One comparison like `<27.2` or `>=1.0`.
public struct VersionConstraint: Sendable, Hashable {
    public enum Op: String, Sendable { case lt = "<", le = "<=", gt = ">", ge = ">=", eq = "=" }
    public let op: Op
    public let version: Version

    public func isSatisfied(by v: Version) -> Bool {
        switch op {
        case .lt: v < version
        case .le: v <= version
        case .gt: v > version
        case .ge: v >= version
        case .eq: v == version
        }
    }
}

/// A version expression as BSI writes it in CSAF branch names, e.g.
/// `<2026.3`, `Golden Gate <27.2`, `Tahoe 26.7.2`, `>=1.0 <2.0`, `vers:generic/>=1.0|<2.0`.
public struct VersionSpec: Sendable, Hashable {
    /// Free text before the first version (often a release line like "Sequoia").
    public let label: String
    /// All constraints must hold.
    public let constraints: [VersionConstraint]

    public static func parse(_ raw: String) -> VersionSpec? {
        var text = raw.trimmingCharacters(in: .whitespaces)
        // Commit hashes ("commit 4da9812") are not versions.
        if isCommitReference(text) { return nil }
        // BSI occasionally writes "=>1.11" / "=<2.0".
        text = text.replacingOccurrences(of: "=>", with: ">=").replacingOccurrences(of: "=<", with: "<=")
        if text.hasPrefix("vers:"), let slash = text.firstIndex(of: "/") {
            text = String(text[text.index(after: slash)...]).replacingOccurrences(of: "|", with: " ")
        }
        let pattern = /(<=|>=|<|>|=)?\s*[vV]?(\d+(?:\.\d+)*)/
        var found: [(op: VersionConstraint.Op?, version: Version, start: String.Index)] = []
        for match in text.matches(of: pattern) {
            guard let version = Version(String(match.output.2)) else { continue }
            let op = match.output.1.flatMap { VersionConstraint.Op(rawValue: String($0)) }
            found.append((op, version, match.range.lowerBound))
        }
        guard !found.isEmpty else { return nil }

        // Bare numbers before the first operator belong to the label ("Office 2019 <16.78").
        if let firstOp = found.firstIndex(where: { $0.op != nil }), firstOp > 0 {
            found.removeFirst(firstOp)
        } else if found.count > 1, found.allSatisfy({ $0.op == nil }) {
            // "Office 2019 16.78": the last bare number is the version.
            found = [found[found.count - 1]]
        }

        let label = String(text[..<found[0].start])
            .trimmingCharacters(in: .whitespaces.union(.punctuationCharacters))
        let constraints = found.map { VersionConstraint(op: $0.op ?? .eq, version: $0.version) }
        return VersionSpec(label: label, constraints: constraints)
    }

    static func isCommitReference(_ text: String) -> Bool {
        let lower = text.lowercased()
        return lower.contains("commit") || lower.contains(/\b(?=[0-9a-f]*[a-f])[0-9a-f]{7,40}\b/)
    }

    public func matches(_ v: Version) -> Bool {
        constraints.allSatisfy { $0.isSatisfied(by: v) }
    }

    /// Upper bound for "<X" / "<=X" constraints, i.e. the first fixed version.
    public var upperBound: Version? {
        constraints.first(where: { $0.op == .lt || $0.op == .le })?.version
    }

    /// True if the label names a platform other than macOS ("iOS <160.0", "Android 3.7.2", "Windows <2.1").
    public var targetsOtherPlatform: Bool {
        Platform.isForeign(label)
    }

    public var exactVersion: Version? {
        constraints.count == 1 && constraints[0].op == .eq ? constraints[0].version : nil
    }
}

public enum Platform {
    static let foreignTokens: Set<String> = ["ios", "ipados", "android", "windows", "win", "linux", "watchos", "tvos", "visionos", "chromeos"]

    /// True if the text names another platform and does not also name the Mac.
    public static func isForeign(_ text: String) -> Bool {
        let tokens = Set(text.lowercased().split { !$0.isLetter }.map(String.init))
        guard !tokens.isDisjoint(with: foreignTokens) else { return false }
        return tokens.isDisjoint(with: ["macos", "mac", "osx", "desktop"])
    }

    /// True for advisory titles that only concern a mobile app, e.g.
    /// "Mozilla Firefox für iOS: …", "VLC für Android: …", "Mozilla Firefox (iOS): …".
    public static func isMobileOnlyTitle(_ title: String) -> Bool {
        let lower = title.lowercased()
        if lower.contains("macos") || lower.contains("mac os") { return false }
        let product = lower.split(separator: ":", maxSplits: 1).first.map(String.init) ?? lower
        return product.contains(/(für|for)\s+(android|ios|ipados)\b/)
            || product.contains(/\((android|ios|ipados)\)/)
            || product.contains(/\b(android|ios)\s*$/)
    }
}

/// Decides whether an installed version is affected by a product's ranges in one advisory.
public enum AffectedEvaluator {
    /// - Parameters:
    ///   - affected: version specs the advisory marks as known affected.
    ///   - fixed: versions the advisory lists as fixed (upper bounds of `affected` are added automatically).
    /// - Returns: the affected spec that matches, or `nil` if the version is not affected.
    ///
    /// BSI lists one range per release line (e.g. `Tahoe <26.7.2`, `Sequoia <15.8.2`).
    /// A version matching *some* range is still considered patched when it is at or above
    /// the fixed version that shares the most leading components with it (its own line).
    public static func matchingSpec(installed rawInstalled: Version, affected: [VersionSpec], fixed: [Version]) -> VersionSpec? {
        let references = fixed + affected.flatMap { $0.constraints.map(\.version) }
        let installed = normalizeYearScheme(rawInstalled, references: references)
        let candidates = affected.filter { $0.matches(installed) }
        guard !candidates.isEmpty else { return nil }

        let allFixed = Set(fixed + affected.compactMap(\.upperBound))
        let bestPrefix = allFixed.map { $0.commonPrefixLength(with: installed) }.max() ?? 0
        if bestPrefix > 0 {
            let lineFixes = allFixed.filter { $0.commonPrefixLength(with: installed) == bestPrefix }
            if lineFixes.contains(where: { installed >= $0 }) { return nil }
        }

        // Report the range belonging to the installed release line if possible.
        return candidates.max { a, b in
            (a.upperBound?.commonPrefixLength(with: installed) ?? -1) < (b.upperBound?.commonPrefixLength(with: installed) ?? -1)
        }
    }

    /// Explains why a formally matching version is still doubtful, or returns nil.
    ///
    /// - No fixed version at all ("ffmpeg >=2.7"): the claim cannot be checked.
    /// - The installed version is far below every version the advisory names and shares no
    ///   leading component with them (Obsidian 1.15 vs. "<6.3.1"): usually a different product
    ///   with the same name, or an old release line the advisory does not consider.
    public static func implausibility(installed rawInstalled: Version, matched: VersionSpec, references: [Version]) -> String? {
        let installed = normalizeYearScheme(rawInstalled, references: references)
        guard !references.isEmpty else {
            return tr("Der Hinweis nennt keine behobene Version – die Angabe lässt sich nicht überprüfen.", "The advisory names no fixed version – the claim cannot be verified.")
        }
        let sharesLine = references.contains { $0.commonPrefixLength(with: installed) > 0 }
        let major = installed.components.first ?? 0
        let lowestMajor = references.compactMap(\.components.first).min() ?? 0
        if !sharesLine, lowestMajor > major + 1 {
            let named = Set(references.map(\.description)).sorted().joined(separator: ", ")
            return tr(
                "Die installierte Version \(rawInstalled) liegt weit unter allen im Hinweis genannten Versionen (\(named)). "
                    + "Vermutlich betrifft der Hinweis ein anderes Produkt gleichen Namens oder eine nicht mehr gepflegte Versionslinie.",
                "The installed version \(rawInstalled) is far below every version the advisory names (\(named)). "
                    + "The advisory probably concerns a different product with the same name or a release line that is no longer maintained."
            )
        }
        return nil
    }

    /// Vendors such as Adobe ship "26.003.22110" while advisories write "2026.003.22110"
    /// (or "2015.006.30527" for older tracks). Lift a two-digit major into the year range
    /// when every reference version uses four-digit years.
    static func normalizeYearScheme(_ v: Version, references: [Version]) -> Version {
        guard let major = v.components.first, major < 100,
              !references.isEmpty,
              references.allSatisfy({ ($0.components.first ?? 0) >= 2000 })
        else { return v }
        return Version(components: [2000 + major] + v.components.dropFirst())
    }
}
