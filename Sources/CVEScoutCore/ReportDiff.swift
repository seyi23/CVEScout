import Foundation

/// Differences between two scans – drives notifications after automatic scans.
public struct ReportDiff: Sendable {
    /// Confirmed findings that were not present in the previous scan.
    public let newFindings: [Finding]
    /// Confirmed findings of the previous scan that disappeared (e.g. software was updated).
    public let resolvedFindings: [Finding]
    /// Checks that are now failing/warning but were passing (or absent) before.
    public let newProblems: [SecurityCheckResult]

    public var isEmpty: Bool { newFindings.isEmpty && newProblems.isEmpty }
    public var hasExploited: Bool { newFindings.contains { !$0.exploited.isEmpty } }

    public init(current: ScanReport, previous: ScanReport?) {
        let oldIDs = Set(previous?.confirmedFindings.map(\.id) ?? [])
        let newIDs = Set(current.confirmedFindings.map(\.id))
        newFindings = current.confirmedFindings.filter { !oldIDs.contains($0.id) }
        resolvedFindings = previous?.confirmedFindings.filter { !newIDs.contains($0.id) } ?? []
        let isProblem: (CheckStatus) -> Bool = { $0 == .fail || $0 == .warning }
        let oldProblems = Set(previous?.checks.filter { isProblem($0.status) }.map(\.id) ?? [])
        newProblems = current.checks.filter { isProblem($0.status) && !oldProblems.contains($0.id) }
    }

    /// Short German summary for a notification, or nil if nothing new.
    public var notificationText: (title: String, body: String)? {
        guard !isEmpty else { return nil }
        var parts: [String] = []
        if !newFindings.isEmpty {
            let programs = Array(Set(newFindings.map(\.software.name))).sorted()
            let list = programs.prefix(3).joined(separator: ", ") + (programs.count > 3 ? " …" : "")
            parts.append(tr("\(newFindings.count) neue Schwachstelle(n): \(list)", "\(newFindings.count) new vulnerabilit\(newFindings.count == 1 ? "y" : "ies"): \(list)"))
        }
        if !newProblems.isEmpty {
            parts.append(tr("Einstellungen: ", "Settings: ") + newProblems.map(\.title).joined(separator: ", "))
        }
        let title = hasExploited ? tr("CVEScout: aktiv ausgenutzte Lücke gefunden", "CVEScout: actively exploited vulnerability found") : tr("CVEScout: neue Sicherheitsprobleme", "CVEScout: new security issues")
        return (title, parts.joined(separator: "\n"))
    }
}

/// How often the app scans on its own while it is running.
public enum AutoScanInterval: Int, CaseIterable, Sendable, Identifiable {
    case off = 0
    case every6Hours = 6
    case every12Hours = 12
    case daily = 24
    case weekly = 168

    public var id: Int { rawValue }

    public var label: String {
        switch self {
        case .off: tr("Aus", "Off")
        case .every6Hours: tr("Alle 6 Stunden", "Every 6 hours")
        case .every12Hours: tr("Alle 12 Stunden", "Every 12 hours")
        case .daily: tr("Täglich", "Daily")
        case .weekly: tr("Wöchentlich", "Weekly")
        }
    }

    public var interval: TimeInterval? { self == .off ? nil : TimeInterval(rawValue) * 3600 }

    /// Whether an automatic scan is due, given the date of the last scan.
    public func isDue(lastScan: Date?, now: Date = Date()) -> Bool {
        guard let interval else { return false }
        guard let lastScan else { return true }
        return now.timeIntervalSince(lastScan) >= interval
    }
}
