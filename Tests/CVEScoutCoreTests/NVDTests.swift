@testable import CVEScoutCore
import Foundation
import Testing

@Suite("NVD matching and update parsing")
struct NVDTests {
    static func cve(_ configurations: String) throws -> NVDCVE {
        let json = """
        {"id": "CVE-2026-0001", "published": "2026-01-01T00:00:00.000",
         "descriptions": [{"lang": "en", "value": "Example app before 4.2.2 allows code execution. More text."}],
         "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 7.8}}]},
         "configurations": \(configurations)}
        """
        return try JSONDecoder().decode(NVDCVE.self, from: Data(json.utf8))
    }

    static let plain = """
    [{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [
      {"vulnerable": true, "criteria": "cpe:2.3:a:example:app:*:*:*:*:*:*:*:*",
       "versionStartIncluding": "4.0", "versionEndExcluding": "4.2.2"}]}]}]
    """

    static let windowsOnly = """
    [{"operator": "AND", "nodes": [
      {"operator": "OR", "negate": false, "cpeMatch": [
        {"vulnerable": true, "criteria": "cpe:2.3:a:example:app:*:*:*:*:*:*:*:*", "versionEndExcluding": "4.2.2"}]},
      {"operator": "OR", "negate": false, "cpeMatch": [
        {"vulnerable": false, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]}]}]
    """

    @Test func matchesRange() throws {
        let c = try Self.cve(Self.plain)
        #expect(c.match(vendor: "example", product: "app", version: Version("4.1")!)?.fixedVersion == "4.2.2")
        #expect(c.match(vendor: "example", product: "app", version: Version("4.2.2")!) == nil)
        #expect(c.match(vendor: "example", product: "app", version: Version("3.9")!) == nil)
        #expect(c.severity == .high)
        #expect(c.asAdvisory().title == "Example app before 4.2.2 allows code execution")
        #expect(c.asAdvisory().origin == .nvd)
    }

    @Test func skipsOtherPlatforms() throws {
        let c = try Self.cve(Self.windowsOnly)
        #expect(c.match(vendor: "example", product: "app", version: Version("4.1")!) == nil)
    }

    @Test func unboundedWildcardIsIgnored() throws {
        let c = try Self.cve("""
        [{"nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": "cpe:2.3:a:example:app:*:*:*:*:*:*:*:*"}]}]}]
        """)
        #expect(c.match(vendor: "example", product: "app", version: Version("1.0")!) == nil)
    }

    @Test func cveListUsesInventory() throws {
        let c = try Self.cve(Self.plain)
        let item = SoftwareItem(name: "App", identifier: "org.example.app", version: "4.1", source: .application)
        let other = SoftwareItem(name: "Other", identifier: "org.other", version: "1.0", source: .application)
        let r = NVDMatching.evaluate(cve: c, inventory: [item, other], kev: .empty)
        #expect(r.status == .affected)
        #expect(r.software == ["App 4.1"])
        #expect(r.source == .nvd)
        let r2 = NVDMatching.evaluate(cve: c, inventory: [other], kev: .empty)
        #expect(r2.status == .notInstalled)
    }

    @Test func pendingUpdates() {
        let out = """
        Software Update found the following new or updated software:
        * Label: macOS Golden Gate 27.2.2-26C50
        \tTitle: macOS Golden Gate 27.2.2, Version: 27.2.2, Size: 1234567KiB, Recommended: YES, Action: restart,
        * Label: Command Line Tools for Xcode-27.2
        \tTitle: Command Line Tools for Xcode, Version: 27.2, Size: 900000KiB, Recommended: YES,
        """
        #expect(SecurityChecks.parsePendingUpdates(out) == ["macOS Golden Gate 27.2.2", "Command Line Tools for Xcode (27.2)"])
        #expect(SecurityChecks.parsePendingUpdates("No new software available.").isEmpty)
    }
}
