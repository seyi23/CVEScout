import Foundation

public enum ReportExport {
    public static func json(_ report: ScanReport) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(report)
    }

    public static func decodeJSON(_ data: Data) throws -> ScanReport {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(ScanReport.self, from: data)
    }

    public static func markdown(_ report: ScanReport) -> String {
        var md = "# CVEScout – Sicherheitsbericht\n\n"
        md += "- Erstellt: \(report.date.formatted(date: .long, time: .shortened))\n"
        md += "- macOS: \(report.osVersion)\n"
        md += "- Erfasste Software: \(report.inventory.count) (davon \(report.mappedSoftwareIDs.count) mit BSI-Zuordnung)\n"
        md += "- Ausgewertete BSI-Hinweise: \(report.advisoriesEvaluated)\n"
        md += "- Zutreffende Einträge: \(report.findings.filter { $0.advisory.origin == .bsi }.count) BSI, \(report.findings.filter { $0.advisory.origin == .nvd }.count) NVD\n"
        if let v = report.kevCatalogVersion { md += "- CISA-KEV-Katalog: \(v)\n" }
        md += "\n## Zusammenfassung\n\n"
        md += "| Betroffene Programme | BSI-Hinweise | CVEs | Aktiv ausgenutzt (KEV) |\n|---|---|---|---|\n"
        md += "| \(report.vulnerableSoftwareCount) | \(report.findings.count) | \(report.uniqueCVECount) | \(report.exploitedCount) |\n\n"

        md += "## Schwachstellen\n\n"
        if report.findings.isEmpty {
            md += "Keine bekannten Schwachstellen für die erfasste Software gefunden.\n\n"
        }
        for f in report.findings {
            md += "### \(f.software.name) \(f.software.version) – \(f.advisory.title)\n\n"
            md += "- Quelle: \(f.advisory.origin.label) [\(f.advisory.id)](\(f.advisory.portalURL?.absoluteString ?? f.advisory.csafURL.absoluteString))\n"
            if let score = f.advisory.cvssScore { md += "- CVSS: \(String(format: "%.1f", score))\n" }
            md += "- Schweregrad: \(f.effectiveSeverity.label)\n"
            md += "- Betroffener Bereich: `\(f.matchedRange)`\n"
            if !f.fixedVersions.isEmpty { md += "- Behoben in: \(f.fixedVersions.joined(separator: ", "))\n" }
            md += "- Zuordnung: \(f.confidence.label)\n"
            md += "- CVEs (\(f.advisory.cves.count)): \(f.advisory.cves.prefix(20).joined(separator: ", "))\(f.advisory.cves.count > 20 ? ", …" : "")\n"
            if !f.exploited.isEmpty {
                md += "- **Aktiv ausgenutzt (CISA KEV):** \(f.exploited.map(\.cveID).joined(separator: ", "))\n"
            }
            md += "\n"
        }

        if let results = report.cveResults {
            md += "## CVE-Liste (\(results.count) Einträge)\n\n| CVE | Status | Software | Quelle | KEV |\n|---|---|---|---|---|\n"
            for r in results {
                let adv = r.advisories.map { "[\($0.id)](\($0.url?.absoluteString ?? ""))" }.joined(separator: ", ")
                md += "| \(r.cve) | \(r.status.label) | \(r.software.joined(separator: ", ")) | \(adv) | \(r.kev == nil ? "" : "ja") |\n"
            }
            md += "\n"
        }

        md += "## Systemprüfungen\n\n| Prüfung | Status | Details |\n|---|---|---|\n"
        for c in report.checks {
            md += "| \(c.title) | \(c.status.label) | \(c.detail.replacingOccurrences(of: "|", with: "\\|")) |\n"
        }
        if !report.warnings.isEmpty {
            md += "\n## Hinweise\n\n" + report.warnings.map { "- \($0)" }.joined(separator: "\n") + "\n"
        }
        md += "\n---\nQuellen: BSI WID/CERT-Bund (CSAF, TLP:WHITE), NIST NVD, CISA Known Exploited Vulnerabilities.\n"
        md += "Versionsabgleich ohne Gewähr – Ergebnisse bitte mit den verlinkten Hinweisen prüfen.\n"
        return md
    }
}
