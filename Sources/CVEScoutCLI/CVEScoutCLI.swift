import CVEScoutCore
import Foundation

// cvescout [--json | --markdown] [--days N] [--no-brew] [--no-apps] [--no-checks] [--refresh]

@main
struct CVEScoutCLI {
    static func log(_ s: String) { FileHandle.standardError.write(Data((s + "\n").utf8)) }

    static func main() async {
        let args = Array(CommandLine.arguments.dropFirst())
        if args.contains("-h") || args.contains("--help") {
            print("""
            Verwendung: cvescout [Optionen]

              --json         Bericht als JSON ausgeben
              --markdown     Bericht als Markdown ausgeben
              --days N       nur BSI-Hinweise der letzten N Tage auswerten (Standard: 730)
              --no-apps      Programme in /Applications nicht prüfen
              --no-brew      Homebrew-Pakete nicht prüfen
              --no-checks    Systemeinstellungen nicht prüfen
              --refresh      BSI-Feed und KEV-Katalog neu herunterladen
              --cves DATEI   zusätzlich eine CVE-Liste prüfen (TXT, eine CVE pro Zeile, # = Kommentar)
              --no-nvd       NVD nicht als zweite Quelle nutzen

            Umgebungsvariable NVD_API_KEY: optionaler NVD-API-Schlüssel (schnellere Abfragen)

            Exit-Code: 0 = nichts gefunden, 1 = Fehler, 2 = Schwachstellen gefunden / CVE betroffen
            """)
            exit(0)
        }

        var options = ScanOptions()
        if let i = args.firstIndex(of: "--days"), i + 1 < args.count, let d = Int(args[i + 1]) { options.lookbackDays = d }
        options.includeApplications = !args.contains("--no-apps")
        options.includeHomebrew = !args.contains("--no-brew")
        options.runSecurityChecks = !args.contains("--no-checks")
        options.forceRefresh = args.contains("--refresh")
        options.useNVD = !args.contains("--no-nvd")
        options.nvdAPIKey = ProcessInfo.processInfo.environment["NVD_API_KEY"]
        if let i = args.firstIndex(of: "--cves") {
            guard i + 1 < args.count else {
                FileHandle.standardError.write(Data("Fehler: --cves erwartet einen Dateipfad.\n".utf8))
                exit(1)
            }
            do {
                let list = try CVEWatchlist.load(from: URL(fileURLWithPath: args[i + 1]))
                guard !list.cves.isEmpty else {
                    FileHandle.standardError.write(Data("Fehler: Keine CVE-IDs in \(args[i + 1]) gefunden.\n".utf8))
                    exit(1)
                }
                options.watchlist = list
            } catch {
                FileHandle.standardError.write(Data("Fehler: \(args[i + 1]) nicht lesbar: \(error.localizedDescription)\n".utf8))
                exit(1)
            }
        }
        let quiet = args.contains("--json") || args.contains("--markdown")


        do {
            let start = Date()
            let report = try await VulnerabilityScanner().run(options: options) { phase in
                if !quiet, phase.fraction == nil || phase == .fetchingAdvisories(done: 0, total: 0) { log(phase.label) }
            }
            if args.contains("--json") {
                FileHandle.standardOutput.write(try ReportExport.json(report))
            } else if args.contains("--markdown") {
                print(ReportExport.markdown(report))
            } else {
                print("\nmacOS \(report.osVersion) · \(report.inventory.count) Programme/Pakete · \(report.mappedSoftwareIDs.count) mit BSI-Zuordnung · \(report.advisoriesEvaluated) BSI-Hinweise ausgewertet (\(Int(Date().timeIntervalSince(start)))s)\n")
                if report.findings.isEmpty {
                    print("✅ Keine bekannten Schwachstellen gefunden.")
                } else {
                    print("⚠️  \(report.findings.count) zutreffende BSI-Hinweise für \(report.vulnerableSoftwareCount) Programme:\n")
                    for f in report.findings {
                        let kev = f.exploited.isEmpty ? "" : "  🔥 \(f.exploited.count)× aktiv ausgenutzt"
                        let score = f.advisory.cvssScore.map { " CVSS \(String(format: "%.1f", $0))" } ?? ""
                        print("  [\(f.effectiveSeverity.label.uppercased())] \(f.software.name) \(f.software.version) – \(f.advisory.origin.label) \(f.advisory.id)\(score): \(f.advisory.title)\(kev)")
                        print("      betroffen: \(f.matchedRange)  →  behoben in: \(f.fixedVersions.joined(separator: ", "))")
                    }
                }
                if let results = report.cveResults {
                    print("\nCVE-Liste (\(results.count) Einträge):")
                    for r in results {
                        let icon = switch r.status { case .affected: "❌"; case .patched: "✅"; case .notInstalled: "➖"; case .unknown: "❓" }
                        let kev = r.kev == nil ? "" : "  🔥 aktiv ausgenutzt"
                        let sw = r.software.isEmpty ? "" : " – \(r.software.joined(separator: ", "))"
                        let adv = r.advisories.first.map { " [\($0.id)\(r.advisories.count > 1 ? " +\(r.advisories.count - 1)" : "")]" } ?? ""
                        let score = r.cvssScore.map { " (CVSS \(String(format: "%.1f", $0)))" } ?? ""
                        print("  \(icon) \(r.cve)\(score): \(r.status.label)\(sw)\(adv)\(kev)")
                    }
                }
                if !report.checks.isEmpty {
                    print("\nSystemprüfungen:")
                    for c in report.checks {
                        let icon = switch c.status { case .pass: "✅"; case .warning: "⚠️ "; case .fail: "❌"; case .info: "ℹ️ "; case .error: "❓" }
                        print("  \(icon) \(c.title): \(c.detail)")
                    }
                }
                for w in report.warnings { print("Hinweis: \(w)") }
            }
            let cveAffected = report.cveResults?.contains { $0.status == .affected } ?? false
            exit(report.findings.isEmpty && !cveAffected ? 0 : 2)
        } catch {
            log("Fehler: \(error.localizedDescription)")
            exit(1)
        }
    }
}
