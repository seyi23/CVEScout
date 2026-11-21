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
        let locale = Language.current.locale
        let bsiCount = report.findings.filter { $0.advisory.origin == .bsi }.count
        let nvdCount = report.findings.filter { $0.advisory.origin == .nvd }.count
        var md = tr("# CVEScout – Sicherheitsbericht\n\n", "# CVEScout – Security report\n\n")
        md += tr("- Erstellt: ", "- Created: ")
            + report.date.formatted(Date.FormatStyle(date: .long, time: .shortened).locale(locale)) + "\n"
        md += "- macOS: \(report.osVersion)\n"
        md += tr("- Erfasste Software: \(report.inventory.count) (davon \(report.mappedSoftwareIDs.count) zugeordnet)\n",
                 "- Software found: \(report.inventory.count) (\(report.mappedSoftwareIDs.count) mapped)\n")
        md += tr("- Ausgewertete BSI-Hinweise: \(report.advisoriesEvaluated)\n",
                 "- BSI advisories evaluated: \(report.advisoriesEvaluated)\n")
        md += tr("- Zutreffende Einträge: \(bsiCount) BSI, \(nvdCount) NVD\n", "- Matching entries: \(bsiCount) BSI, \(nvdCount) NVD\n")
        if let v = report.kevCatalogVersion { md += tr("- CISA-KEV-Katalog: \(v)\n", "- CISA KEV catalog: \(v)\n") }

        md += tr("\n## Zusammenfassung\n\n", "\n## Summary\n\n")
        md += tr("| Betroffene Programme | Hinweise | Unsichere Treffer | CVEs | Aktiv ausgenutzt (KEV) |\n",
                 "| Affected apps | Advisories | Uncertain matches | CVEs | Actively exploited (KEV) |\n")
        md += "|---|---|---|---|---|\n"
        md += "| \(report.vulnerableSoftwareCount) | \(report.confirmedFindings.count) | \(report.uncertainFindings.count) | \(report.uniqueCVECount) | \(report.exploitedCount) |\n\n"

        md += tr("## Schwachstellen\n\n", "## Vulnerabilities\n\n")
        if report.findings.isEmpty {
            md += tr("Keine bekannten Schwachstellen für die erfasste Software gefunden.\n\n",
                     "No known vulnerabilities found for the installed software.\n\n")
        }
        for f in report.findings {
            md += "### \(f.software.name) \(f.software.version) – \(f.advisory.title)\n\n"
            let link = f.advisory.portalURL?.absoluteString ?? f.advisory.csafURL.absoluteString
            md += tr("- Quelle: ", "- Source: ") + "\(f.advisory.origin.label) [\(f.advisory.id)](\(link))\n"
            if let score = f.advisory.cvssScore { md += "- CVSS: \(String(format: "%.1f", score))\n" }
            md += tr("- Schweregrad: ", "- Severity: ") + f.effectiveSeverity.label + "\n"
            md += tr("- Betroffener Bereich: ", "- Affected range: ") + "`\(f.matchedRange)`\n"
            if !f.fixedVersions.isEmpty {
                md += tr("- Behoben in: ", "- Fixed in: ") + f.fixedVersions.joined(separator: ", ") + "\n"
            }
            md += tr("- Zuordnung: ", "- Mapping: ") + f.confidence.label + "\n"
            if let reason = f.uncertainReason { md += tr("- **Unsicherer Treffer:** ", "- **Uncertain match:** ") + reason + "\n" }
            let cves = f.advisory.cves.prefix(20).joined(separator: ", ") + (f.advisory.cves.count > 20 ? ", …" : "")
            md += "- CVEs (\(f.advisory.cves.count)): \(cves)\n"
            if !f.exploited.isEmpty {
                md += tr("- **Aktiv ausgenutzt (CISA KEV):** ", "- **Actively exploited (CISA KEV):** ")
                    + f.exploited.map(\.cveID).joined(separator: ", ") + "\n"
            }
            md += "\n"
        }

        if let results = report.cveResults {
            md += tr("## CVE-Liste (\(results.count) Einträge)\n\n", "## CVE list (\(results.count) entries)\n\n")
            md += tr("| CVE | Status | Software | Quelle | KEV |\n", "| CVE | Status | Software | Source | KEV |\n")
            md += "|---|---|---|---|---|\n"
            for r in results {
                let adv = r.advisories.map { "[\($0.id)](\($0.url?.absoluteString ?? ""))" }.joined(separator: ", ")
                let kev = r.kev == nil ? "" : tr("ja", "yes")
                md += "| \(r.cve) | \(r.status.label) | \(r.software.joined(separator: ", ")) | \(adv) | \(kev) |\n"
            }
            md += "\n"
        }

        md += tr("## Systemprüfungen\n\n| Prüfung | Status | Details |\n", "## System checks\n\n| Check | Status | Details |\n")
        md += "|---|---|---|\n"
        for c in report.checks {
            md += "| \(c.title) | \(c.status.label) | \(c.detail.replacingOccurrences(of: "|", with: "\\|")) |\n"
        }
        if !report.warnings.isEmpty {
            md += tr("\n## Hinweise\n\n", "\n## Notes\n\n") + report.warnings.map { "- \($0)" }.joined(separator: "\n") + "\n"
        }
        md += "\n---\n\(DataSources.attribution)\n"
        md += tr("Versionsabgleich ohne Gewähr – Ergebnisse bitte mit den verlinkten Hinweisen prüfen.\n",
                 "Version matching without warranty – please verify results against the linked advisories.\n")
        return md
    }
}
