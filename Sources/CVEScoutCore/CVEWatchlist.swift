import Foundation

/// A user-supplied list of CVE ids to check explicitly (TXT file, one CVE per line).
public struct CVEWatchlist: Sendable, Codable, Hashable {
    public let cves: [String]
    /// Non-empty lines that did not contain a CVE id (shown to the user).
    public let invalidLines: [String]

    public init(cves: [String], invalidLines: [String] = []) {
        self.cves = cves
        self.invalidLines = invalidLines
    }

    /// Parses text with one CVE per line. Blank lines and lines starting with `#` are ignored;
    /// text after the id (e.g. "CVE-2024-3094  xz backdoor") is allowed. Duplicates are removed.
    public static func parse(_ text: String) -> CVEWatchlist {
        var cves: [String] = []
        var seen = Set<String>()
        var invalid: [String] = []
        for rawLine in text.components(separatedBy: .newlines) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }
            guard let match = line.firstMatch(of: /(?i)CVE-\d{4}-\d{4,}/) else {
                invalid.append(line)
                continue
            }
            let id = String(line[match.range]).uppercased()
            if seen.insert(id).inserted { cves.append(id) }
        }
        return CVEWatchlist(cves: cves, invalidLines: invalid)
    }

    public static func load(from url: URL) throws -> CVEWatchlist {
        parse(try String(contentsOf: url, encoding: .utf8))
    }
}

public enum CVEStatus: String, Codable, Sendable, CaseIterable {
    /// Installed software is in an affected version range.
    case affected
    /// Product is installed, but the installed version is outside all affected ranges.
    case patched
    /// BSI lists the CVE, but none of the affected products is installed (or mapped).
    case notInstalled
    /// Neither the BSI nor (if enabled) the NVD has usable data for this CVE.
    case unknown

    public var label: String {
        switch self {
        case .affected: "Betroffen"
        case .patched: "Nicht betroffen"
        case .notInstalled: "Produkt nicht installiert"
        case .unknown: "Keine Daten"
        }
    }
}

public struct CVECheckResult: Codable, Sendable, Identifiable, Hashable {
    public var id: String { cve }
    public let cve: String
    public let status: CVEStatus
    /// BSI advisories that mention the CVE.
    public let advisories: [AdvisoryRef]
    /// Installed software that is affected (status .affected) or was checked (status .patched).
    public let software: [String]
    /// Affected ranges that matched, e.g. "Google Chrome <157.0.8103.50".
    public let matchedRanges: [String]
    public let kev: KEVEntry?
    /// Where the verdict comes from (nil = BSI, reports from 0.1).
    public var source: AdvisorySource? = nil
    /// NVD description and CVSS base score (filled when the NVD was consulted).
    public var summary: String? = nil
    public var cvssScore: Double? = nil

    public struct AdvisoryRef: Codable, Sendable, Hashable {
        public let id: String
        public let title: String
        public let url: URL?
    }

    public var nvdURL: URL? { URL(string: "https://nvd.nist.gov/vuln/detail/\(cve)") }
}

extension CVEWatchlist {
    /// Evaluates every CVE of the list against the mapped local software.
    func evaluate(feed: BSIFeedIndex,
                  advisories: [String: CSAFAdvisory],
                  mappings: [ProductCatalog.Mapping],
                  kev: KEVCatalog) -> [CVECheckResult] {
        cves.map { cve in
            let docs = feed.entries(forCVE: cve).compactMap { advisories[$0.id] }
            let refs = docs.map { doc in
                CVECheckResult.AdvisoryRef(id: doc.advisory.id, title: doc.advisory.title,
                                           url: doc.advisory.portalURL ?? doc.advisory.csafURL)
            }
            var affected: [String] = [], ranges: [String] = [], checked: [String] = []
            for doc in docs {
                for mapping in mappings {
                    guard let version = Version(mapping.item.version) else { continue }
                    for ref in mapping.refs where !doc.leaves(for: ref).isEmpty {
                        let label = "\(mapping.item.name) \(mapping.item.version)"
                        if let hit = doc.evaluate(ref: ref, version: version, cve: cve) {
                            affected.append(label)
                            ranges.append(hit.leaf.fullName)
                        } else {
                            checked.append(label)
                        }
                    }
                }
            }
            let status: CVEStatus
            if docs.isEmpty { status = .unknown }
            else if !affected.isEmpty { status = .affected }
            else if !checked.isEmpty { status = .patched }
            else { status = .notInstalled }
            return CVECheckResult(
                cve: cve, status: status, advisories: refs,
                software: Array(Set(status == .affected ? affected : checked)).sorted(),
                matchedRanges: Array(Set(ranges)).sorted(),
                kev: kev.entries[cve]
            )
        }
    }
}
