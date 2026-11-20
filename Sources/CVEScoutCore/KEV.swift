import Foundation

/// CISA Known Exploited Vulnerabilities catalog – CVEs that are actively exploited in the wild.
public struct KEVCatalog: Sendable {
    public static let url = URL(string: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")!

    public let version: String
    public let entries: [String: KEVEntry]

    private struct Payload: Decodable {
        let catalogVersion: String
        let vulnerabilities: [KEVEntry]
    }

    public static func decode(_ data: Data) throws -> KEVCatalog {
        let payload = try JSONDecoder().decode(Payload.self, from: data)
        var map: [String: KEVEntry] = [:]
        for e in payload.vulnerabilities { map[e.cveID] = e }
        return KEVCatalog(version: payload.catalogVersion, entries: map)
    }

    public static let empty = KEVCatalog(version: "", entries: [:])
}
