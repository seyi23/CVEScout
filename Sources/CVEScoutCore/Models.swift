import Foundation

// MARK: - Inventory

public enum SoftwareSource: String, Codable, Sendable, CaseIterable {
    case system
    case application
    case homebrew

    public var label: String {
        switch self {
        case .system: "Betriebssystem"
        case .application: "Programm"
        case .homebrew: "Homebrew"
        }
    }
}

/// One piece of locally installed software with a version we can compare.
public struct SoftwareItem: Codable, Sendable, Hashable, Identifiable {
    public var id: String { "\(source.rawValue):\(identifier)" }
    public let name: String
    /// Bundle identifier, Homebrew formula name, or "macos".
    public let identifier: String
    public let version: String
    public let source: SoftwareSource
    public let path: String?

    public init(name: String, identifier: String, version: String, source: SoftwareSource, path: String? = nil) {
        self.name = name
        self.identifier = identifier
        self.version = version
        self.source = source
        self.path = path
    }
}

// MARK: - Advisories

public enum Severity: Int, Codable, Sendable, Comparable, CaseIterable {
    case unknown = 0, low, medium, high, critical

    /// Maps the BSI `aggregate_severity` text ("niedrig", "mittel", "hoch", "kritisch").
    public init(bsiText: String?) {
        switch bsiText?.lowercased().trimmingCharacters(in: .whitespaces) {
        case "niedrig", "low": self = .low
        case "mittel", "medium": self = .medium
        case "hoch", "high": self = .high
        case "kritisch", "critical": self = .critical
        default: self = .unknown
        }
    }

    public var label: String {
        switch self {
        case .unknown: "unbekannt"
        case .low: "niedrig"
        case .medium: "mittel"
        case .high: "hoch"
        case .critical: "kritisch"
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rawValue < rhs.rawValue }
}

public enum AdvisorySource: String, Codable, Sendable {
    case bsi, nvd

    public var label: String {
        switch self {
        case .bsi: "BSI"
        case .nvd: "NVD"
        }
    }
}

/// A security advisory: a BSI WID / CERT-Bund CSAF document, or a single NVD CVE record.
public struct Advisory: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    public let title: String
    public let severity: Severity
    public let published: Date?
    public let updated: Date?
    public let summary: String?
    public let csafURL: URL
    public let portalURL: URL?
    public let cves: [String]
    /// nil in reports written by 0.1 (always BSI then).
    public var source: AdvisorySource? = nil
    public var cvssScore: Double? = nil

    public var origin: AdvisorySource { source ?? .bsi }
}

/// Vendor/product pair as named in the BSI CSAF product tree.
public struct ProductRef: Codable, Sendable, Hashable {
    public let vendor: String
    public let product: String

    public init(_ vendor: String, _ product: String) {
        self.vendor = vendor
        self.product = product
    }
}

public enum MatchConfidence: String, Codable, Sendable {
    /// Software → BSI product mapping comes from the curated catalog.
    case curated
    /// Derived from app name + vendor appearing in the bundle identifier.
    case heuristic
    /// Software → NVD CPE mapping from the curated catalog.
    case cpe

    public var label: String {
        switch self {
        case .curated: "gesichert"
        case .heuristic: "heuristisch"
        case .cpe: "gesichert (NVD/CPE)"
        }
    }
}

/// Entry from the CISA Known Exploited Vulnerabilities catalog.
public struct KEVEntry: Codable, Sendable, Hashable {
    public let cveID: String
    public let vendorProject: String
    public let product: String
    public let vulnerabilityName: String
    public let dateAdded: String
    public let shortDescription: String
    public let requiredAction: String
    public let knownRansomwareCampaignUse: String

    public var usedInRansomware: Bool { knownRansomwareCampaignUse.lowercased() == "known" }
}

/// A piece of installed software that falls into an affected version range of an advisory.
public struct Finding: Codable, Sendable, Identifiable, Hashable {
    public var id: String { "\(software.id)|\(advisory.id)" }
    public let software: SoftwareItem
    public let advisory: Advisory
    public let product: ProductRef
    /// The affected range from the advisory that matched, e.g. "Apple macOS Sequoia <15.8.2".
    public let matchedRange: String
    /// Versions the advisory lists as fixed for this product.
    public let fixedVersions: [String]
    /// CVEs of this advisory that are listed in CISA KEV (actively exploited).
    public let exploited: [KEVEntry]
    public let confidence: MatchConfidence

    /// Severity raised to critical when any CVE is known to be exploited in the wild.
    public var effectiveSeverity: Severity {
        exploited.isEmpty ? advisory.severity : max(advisory.severity, .critical)
    }
}

// MARK: - Local security checks

public enum CheckStatus: String, Codable, Sendable {
    case pass, warning, fail, info, error

    public var label: String {
        switch self {
        case .pass: "OK"
        case .warning: "Warnung"
        case .fail: "Kritisch"
        case .info: "Info"
        case .error: "Fehler"
        }
    }
}

public struct SecurityCheckResult: Codable, Sendable, Identifiable, Hashable {
    public let id: String
    public let title: String
    public let status: CheckStatus
    public let detail: String
    public let recommendation: String?

    public init(id: String, title: String, status: CheckStatus, detail: String, recommendation: String? = nil) {
        self.id = id
        self.title = title
        self.status = status
        self.detail = detail
        self.recommendation = recommendation
    }
}

// MARK: - Report

public struct ScanReport: Codable, Sendable {
    public let date: Date
    public let osVersion: String
    public let inventory: [SoftwareItem]
    public let findings: [Finding]
    public let checks: [SecurityCheckResult]
    /// Software for which a BSI product mapping exists (curated or heuristic).
    public let mappedSoftwareIDs: [String]
    public let advisoriesEvaluated: Int
    public let bsiFeedDate: Date?
    public let kevCatalogVersion: String?
    public let warnings: [String]
    /// Results for a user-supplied CVE list (nil if none was given).
    public var cveResults: [CVECheckResult]? = nil

    public init(date: Date, osVersion: String, inventory: [SoftwareItem], findings: [Finding],
                checks: [SecurityCheckResult], mappedSoftwareIDs: [String], advisoriesEvaluated: Int,
                bsiFeedDate: Date?, kevCatalogVersion: String?, warnings: [String],
                cveResults: [CVECheckResult]? = nil) {
        self.date = date
        self.osVersion = osVersion
        self.inventory = inventory
        self.findings = findings
        self.checks = checks
        self.mappedSoftwareIDs = mappedSoftwareIDs
        self.advisoriesEvaluated = advisoriesEvaluated
        self.bsiFeedDate = bsiFeedDate
        self.kevCatalogVersion = kevCatalogVersion
        self.warnings = warnings
        self.cveResults = cveResults
    }

    public func findings(for item: SoftwareItem) -> [Finding] {
        findings.filter { $0.software.id == item.id }
    }

    public var vulnerableSoftwareCount: Int { Set(findings.map(\.software.id)).count }
    public var exploitedCount: Int { Set(findings.flatMap { $0.exploited.map(\.cveID) }).count }
    public var uniqueCVECount: Int { Set(findings.flatMap(\.advisory.cves)).count }
}
