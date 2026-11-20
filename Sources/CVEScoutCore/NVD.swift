import Foundation

/// NIST National Vulnerability Database (API 2.0) as a second source next to the BSI.
///
/// Used for software the BSI does not cover (many Mac apps) and for CVEs of a user's
/// CVE list that no BSI advisory mentions. Without an API key the NVD allows
/// 5 requests per 30 seconds, so responses are cached for 24 hours.
public struct NVDClient: Sendable {
    public static let baseURL = URL(string: "https://services.nvd.nist.gov/rest/json/cves/2.0")!

    let cache: DataCache
    let apiKey: String?
    let limiter: RateLimiter

    public init(cache: DataCache, apiKey: String? = nil) {
        self.cache = cache
        let key = apiKey?.trimmingCharacters(in: .whitespacesAndNewlines)
        self.apiKey = (key?.isEmpty ?? true) ? nil : key
        // Public limits: 5 req / 30 s without key, 50 req / 30 s with key.
        self.limiter = RateLimiter(interval: self.apiKey == nil ? 6.2 : 0.65)
    }

    /// CVEs whose configurations match the given CPE name (NVD does the version range matching).
    public func vulnerabilities(cpeName: String) async throws -> [NVDCVE] {
        var all: [NVDCVE] = []
        var start = 0
        repeat {
            var comps = URLComponents(url: Self.baseURL, resolvingAgainstBaseURL: false)!
            comps.queryItems = [
                .init(name: "cpeName", value: cpeName),
                .init(name: "resultsPerPage", value: "2000"),
                .init(name: "startIndex", value: String(start)),
            ]
            let page = try await fetch(comps.url!, key: "nvd-cpe-\(cpeName)-\(start).json")
            all += page.vulnerabilities.map(\.cve)
            start += page.resultsPerPage
            if page.resultsPerPage == 0 || start >= page.totalResults { break }
        } while true
        return all
    }

    public func cve(_ id: String) async throws -> NVDCVE? {
        var comps = URLComponents(url: Self.baseURL, resolvingAgainstBaseURL: false)!
        comps.queryItems = [.init(name: "cveId", value: id)]
        return try await fetch(comps.url!, key: "nvd-cve-\(id).json").vulnerabilities.first?.cve
    }

    private func fetch(_ url: URL, key: String) async throws -> NVDResponse {
        let headers = apiKey.map { ["apiKey": $0] } ?? [:]
        do {
            let entry = try await cache.data(for: url, key: key, maxAge: 24 * 3600, headers: headers, throttle: limiter)
            return try JSONDecoder().decode(NVDResponse.self, from: entry.data)
        } catch is DecodingError {
            throw URLError(.cannotParseResponse)
        } catch {
            // NVD answers 403/503 when the rate limit is hit: wait and try once more.
            try await Task.sleep(for: .seconds(apiKey == nil ? 12 : 3))
            let entry = try await cache.data(for: url, key: key, maxAge: 24 * 3600, headers: headers, throttle: limiter)
            return try JSONDecoder().decode(NVDResponse.self, from: entry.data)
        }
    }
}

/// Spaces out network requests (only requests that actually hit the network wait).
public actor RateLimiter {
    private let interval: TimeInterval
    private var next = Date.distantPast

    public init(interval: TimeInterval) {
        self.interval = interval
    }

    public func wait() async {
        let now = Date()
        let slot = max(now, next)
        next = slot.addingTimeInterval(interval)
        let delay = slot.timeIntervalSince(now)
        if delay > 0 { try? await Task.sleep(for: .seconds(delay)) }
    }
}

// MARK: - Response model

struct NVDResponse: Decodable {
    let resultsPerPage: Int
    let startIndex: Int
    let totalResults: Int
    let vulnerabilities: [Item]
    struct Item: Decodable { let cve: NVDCVE }
}

public struct NVDCVE: Decodable, Sendable {
    public let id: String
    public let published: String?
    public let lastModified: String?
    let descriptions: [Description]?
    let metrics: Metrics?
    let configurations: [Configuration]?

    struct Description: Decodable, Sendable { let lang: String; let value: String }
    struct Metrics: Decodable, Sendable {
        let cvssMetricV40: [Metric]?
        let cvssMetricV31: [Metric]?
        let cvssMetricV30: [Metric]?
        let cvssMetricV2: [Metric]?
    }
    struct Metric: Decodable, Sendable {
        let type: String?
        let cvssData: CVSSData
    }
    struct CVSSData: Decodable, Sendable { let baseScore: Double }
    struct Configuration: Decodable, Sendable { let nodes: [Node] }
    struct Node: Decodable, Sendable {
        let `operator`: String?
        let negate: Bool?
        let cpeMatch: [CPEMatch]
    }

    public struct CPEMatch: Decodable, Sendable {
        public let vulnerable: Bool
        public let criteria: String
        public let versionStartIncluding: String?
        public let versionStartExcluding: String?
        public let versionEndIncluding: String?
        public let versionEndExcluding: String?

        var parts: [String] { criteria.components(separatedBy: ":") }
        var vendor: String { parts.count > 3 ? parts[3] : "" }
        var product: String { parts.count > 4 ? parts[4] : "" }
        var version: String { parts.count > 5 ? parts[5] : "*" }
        var targetSoftware: String { parts.count > 10 ? parts[10] : "*" }
        var hasBounds: Bool {
            versionStartIncluding != nil || versionStartExcluding != nil
                || versionEndIncluding != nil || versionEndExcluding != nil
        }

        /// Human-readable range, e.g. "electrum:electrum <4.2.2".
        public var rangeDescription: String {
            var s = "\(vendor):\(product)"
            if version != "*", version != "-" { s += " \(version)" }
            if let v = versionStartIncluding { s += " >=\(v)" }
            if let v = versionStartExcluding { s += " >\(v)" }
            if let v = versionEndIncluding { s += " <=\(v)" }
            if let v = versionEndExcluding { s += " <\(v)" }
            return s
        }

        public var fixedVersion: String? { versionEndExcluding }

        func matches(_ v: Version) -> Bool {
            if version != "*", version != "-" {
                return Version(version).map { $0 == v } ?? false
            }
            // "all versions" without any bound is mostly noise (e.g. generic CWE-style entries).
            guard hasBounds else { return false }
            if let s = versionStartIncluding.flatMap(Version.init), v < s { return false }
            if let s = versionStartExcluding.flatMap(Version.init), v <= s { return false }
            if let e = versionEndIncluding.flatMap(Version.init), v > e { return false }
            if let e = versionEndExcluding.flatMap(Version.init), v >= e { return false }
            return true
        }
    }

    public var summary: String? {
        (descriptions?.first { $0.lang == "en" } ?? descriptions?.first)?.value
    }

    public var baseScore: Double? {
        let m = metrics
        let lists = [m?.cvssMetricV40, m?.cvssMetricV31, m?.cvssMetricV30, m?.cvssMetricV2]
        for list in lists {
            guard let list, !list.isEmpty else { continue }
            return (list.first { $0.type == "Primary" } ?? list[0]).cvssData.baseScore
        }
        return nil
    }

    public var severity: Severity {
        guard let s = baseScore else { return .unknown }
        switch s {
        case 9...: return .critical
        case 7..<9: return .high
        case 4..<7: return .medium
        case 0.1..<4: return .low
        default: return .unknown
        }
    }

    public var detailURL: URL { URL(string: "https://nvd.nist.gov/vuln/detail/\(id)")! }

    /// Platforms in CPE "target_sw" that are not the Mac.
    static let foreignTargets: Set<String> = ["android", "iphone_os", "ios", "ipados", "windows", "linux", "chrome_os", "windows_phone"]

    /// Returns the vulnerable CPE match for `vendor:product` that contains `version`, if any.
    /// Configurations that only apply on another operating system (AND-node with e.g. Windows) are skipped.
    public func match(vendor: String, product: String, version: Version) -> CPEMatch? {
        for config in configurations ?? [] {
            let platformCriteria = config.nodes.flatMap(\.cpeMatch).filter { !$0.vulnerable && $0.parts.count > 2 && $0.parts[2] == "o" }
            if !platformCriteria.isEmpty, !platformCriteria.contains(where: { $0.criteria.contains(":apple:mac") }) {
                continue
            }
            for node in config.nodes where node.negate != true {
                for m in node.cpeMatch where m.vulnerable
                    && m.vendor == vendor && m.product == product
                    && !Self.foreignTargets.contains(m.targetSoftware)
                    && m.matches(version) {
                    return m
                }
            }
        }
        return nil
    }

    /// All vulnerable vendor/product pairs named in the configurations.
    public var affectedProducts: Set<String> {
        Set((configurations ?? []).flatMap(\.nodes).flatMap(\.cpeMatch).filter(\.vulnerable).map { "\($0.vendor):\($0.product)" })
    }

    /// Wraps the CVE as an `Advisory` so it can be shown like a BSI finding.
    public func asAdvisory() -> Advisory {
        let text = summary ?? id
        let firstSentence = text.range(of: ". ").map { String(text[..<$0.lowerBound]) } ?? text
        let title = firstSentence.count > 140 ? String(firstSentence.prefix(137)) + "…" : firstSentence
        return Advisory(
            id: id, title: title, severity: severity,
            published: DateParsing.iso8601(published.map { $0 + "Z" }) ?? DateParsing.iso8601(published),
            updated: DateParsing.iso8601(lastModified.map { $0 + "Z" }) ?? DateParsing.iso8601(lastModified),
            summary: summary, csafURL: detailURL, portalURL: detailURL, cves: [id],
            source: .nvd, cvssScore: baseScore
        )
    }
}

/// A product as named in NVD CPE 2.3 (`cpe:2.3:a:<vendor>:<product>:<version>:…`).
public struct CPEProduct: Sendable, Hashable, Codable {
    public let vendor: String
    public let product: String

    public init(_ vendor: String, _ product: String) {
        self.vendor = vendor
        self.product = product
    }

    public func cpeName(version: String) -> String {
        "cpe:2.3:a:\(vendor):\(product):\(version):*:*:*:*:*:*:*"
    }
}
