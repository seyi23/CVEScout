@testable import CVEScoutCore
import Foundation
import Testing

@Suite("CSAF documents and CVE lists")
struct CSAFTests {
    static let sample = """
    {
      "document": {
        "title": "Google Chrome: Mehrere Schwachstellen",
        "aggregate_severity": {"text": "hoch"},
        "tracking": {"id": "WID-SEC-W-2026-0001", "initial_release_date": "2026-01-01T23:00:00.000+00:00",
                     "current_release_date": "2026-01-02T23:00:00.000+00:00"},
        "notes": [{"category": "summary", "text": "Ein Angreifer kann Code ausführen."}]
      },
      "product_tree": {"branches": [{"category": "vendor", "name": "Google", "branches": [
        {"category": "product_name", "name": "Chrome", "branches": [
          {"category": "product_version_range", "name": "<140.0.1",
           "product": {"product_id": "T1", "name": "Google Chrome <140.0.1"}},
          {"category": "product_version", "name": "140.0.1",
           "product": {"product_id": "T1-fixed", "name": "Google Chrome 140.0.1"}},
          {"category": "product_version_range", "name": "iOS <140.0",
           "product": {"product_id": "T2", "name": "Google Chrome iOS <140.0"}}
        ]}
      ]}]},
      "vulnerabilities": [
        {"cve": "CVE-2026-1111", "product_status": {"known_affected": ["T1", "T2"]}},
        {"cve": "CVE-2026-2222", "product_status": {"known_affected": ["T2"]}}
      ]
    }
    """

    func advisory() throws -> CSAFAdvisory {
        try CSAFAdvisory.decode(Data(Self.sample.utf8), csafURL: URL(string: "https://example.org/a.json")!)
    }

    @Test func decodesMetadata() throws {
        let a = try advisory()
        #expect(a.advisory.id == "WID-SEC-W-2026-0001")
        #expect(a.advisory.severity == .high)
        #expect(a.advisory.cves == ["CVE-2026-1111", "CVE-2026-2222"])
        #expect(a.advisory.summary == "Ein Angreifer kann Code ausführen.")
        #expect(a.advisory.portalURL?.absoluteString.contains("WID-SEC-2026-0001") == true)
        #expect(a.leaves.count == 3)
    }

    @Test func evaluatesVersions() throws {
        let a = try advisory()
        let chrome = ProductRef("Google", "Chrome")
        let hit = a.evaluate(ref: chrome, version: Version("139.5")!)
        #expect(hit?.leaf.productID == "T1")
        #expect(hit?.fixed == ["140.0.1"])
        #expect(a.evaluate(ref: chrome, version: Version("140.0.1")!) == nil)
        #expect(a.evaluate(ref: ProductRef("Mozilla", "Firefox"), version: Version("1.0")!) == nil)
    }

    @Test func perCVEEvaluationIgnoresOtherPlatforms() throws {
        let a = try advisory()
        let chrome = ProductRef("Google", "Chrome")
        #expect(a.evaluate(ref: chrome, version: Version("139.5")!, cve: "CVE-2026-1111") != nil)
        // CVE-2026-2222 only affects the iOS app.
        #expect(a.evaluate(ref: chrome, version: Version("139.5")!, cve: "CVE-2026-2222") == nil)
    }

    @Test func parsesCVEList() {
        let list = CVEWatchlist.parse("""
        # Kommentar
        CVE-2024-3094   xz backdoor
        cve-2021-44228

        CVE-2024-3094
        keine CVE hier
        """)
        #expect(list.cves == ["CVE-2024-3094", "CVE-2021-44228"])
        #expect(list.invalidLines == ["keine CVE hier"])
    }

    @Test func severityMapping() {
        #expect(Severity(bsiText: "kritisch") == .critical)
        #expect(Severity(bsiText: "Mittel") == .medium)
        #expect(Severity(bsiText: nil) == .unknown)
    }

    @Test func netstatParsing() {
        let out = """
        tcp4       0      0  *.22                   *.*                    LISTEN
        tcp4       0      0  127.0.0.1.5432         *.*                    LISTEN
        tcp6       0      0  *.5900                 *.*                    LISTEN
        tcp4       0      0  192.168.1.5.50000      17.1.1.1.443           ESTABLISHED
        """
        #expect(SecurityChecks.parseListeningPorts(out) == [22, 5900])
    }
}
