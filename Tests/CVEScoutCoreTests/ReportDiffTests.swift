@testable import CVEScoutCore
import Foundation
import Testing

@Suite("Scan diff and scheduling")
struct ReportDiffTests {
    static let url = URL(string: "https://example.org")!

    func finding(_ app: String, _ advisory: String, exploited: Bool = false, uncertain: Bool = false) -> Finding {
        let sw = SoftwareItem(name: app, identifier: app.lowercased(), version: "1.0", source: .application)
        let adv = Advisory(id: advisory, title: advisory, severity: .high, published: nil, updated: nil,
                           summary: nil, csafURL: Self.url, portalURL: nil, cves: ["CVE-2026-1"])
        let kev = exploited ? [KEVEntry(cveID: "CVE-2026-1", vendorProject: "x", product: "y", vulnerabilityName: "z",
                                        dateAdded: "2026-01-01", shortDescription: "", requiredAction: "",
                                        knownRansomwareCampaignUse: "Unknown")] : []
        return Finding(software: sw, advisory: adv, product: ProductRef("x", app), matchedRange: "<2",
                       fixedVersions: ["2"], exploited: kev, confidence: .curated,
                       uncertainReason: uncertain ? "zweifelhaft" : nil)
    }

    func report(_ findings: [Finding], checks: [SecurityCheckResult] = [], date: Date = Date()) -> ScanReport {
        ScanReport(date: date, osVersion: "27.2", inventory: [], findings: findings, checks: checks,
                   mappedSoftwareIDs: [], advisoriesEvaluated: 0, bsiFeedDate: nil, kevCatalogVersion: nil, warnings: [])
    }

    @Test func detectsNewAndResolved() {
        let old = report([finding("Chrome", "A"), finding("Zoom", "B")])
        let new = report([finding("Chrome", "A"), finding("Firefox", "C", exploited: true), finding("Obsidian", "D", uncertain: true)])
        let diff = ReportDiff(current: new, previous: old)
        #expect(diff.newFindings.map(\.advisory.id) == ["C"])          // uncertain ones never notify
        #expect(diff.resolvedFindings.map(\.advisory.id) == ["B"])
        #expect(diff.hasExploited)
        #expect(diff.notificationText?.title.contains("aktiv ausgenutzt") == true)
    }

    @Test func nothingNew() {
        let r = report([finding("Chrome", "A")])
        #expect(ReportDiff(current: r, previous: r).notificationText == nil)
    }

    @Test func newCheckProblems() {
        let ok = SecurityCheckResult(id: "fw", title: "Firewall", status: .pass, detail: "")
        let bad = SecurityCheckResult(id: "fw", title: "Firewall", status: .warning, detail: "")
        let diff = ReportDiff(current: report([], checks: [bad]), previous: report([], checks: [ok]))
        #expect(diff.newProblems.map(\.id) == ["fw"])
        #expect(ReportDiff(current: report([], checks: [bad]), previous: report([], checks: [bad])).isEmpty)
    }

    @Test func schedule() {
        let now = Date()
        #expect(AutoScanInterval.daily.isDue(lastScan: nil, now: now))
        #expect(!AutoScanInterval.daily.isDue(lastScan: now.addingTimeInterval(-3600), now: now))
        #expect(AutoScanInterval.daily.isDue(lastScan: now.addingTimeInterval(-25 * 3600), now: now))
        #expect(!AutoScanInterval.off.isDue(lastScan: nil, now: now))
    }
}
