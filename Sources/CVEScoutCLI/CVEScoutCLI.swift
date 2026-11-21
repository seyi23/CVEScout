import CVEScoutCore
import Foundation

// cvescout [--json | --markdown] [--days N] [--no-apps] [--no-brew] [--no-checks] [--no-nvd]
//          [--refresh] [--cves FILE] [--lang de|en]

@main
struct CVEScoutCLI {
    static func log(_ s: String) { FileHandle.standardError.write(Data((s + "\n").utf8)) }

    static func fail(_ message: String) -> Never {
        log(tr("Fehler: ", "Error: ") + message)
        exit(1)
    }

    static var help: String {
        tr("""
        Verwendung: cvescout [Optionen]

          --json         Bericht als JSON ausgeben
          --markdown     Bericht als Markdown ausgeben
          --days N       nur BSI-Hinweise der letzten N Tage auswerten (Standard: 730)
          --no-apps      Programme in /Applications nicht prüfen
          --no-brew      Homebrew-Pakete nicht prüfen
          --no-checks    Systemeinstellungen nicht prüfen
          --no-nvd       NVD nicht als zweite Quelle nutzen
          --refresh      BSI-Feed und KEV-Katalog neu herunterladen
          --cves DATEI   zusätzlich eine CVE-Liste prüfen (TXT, eine CVE pro Zeile, # = Kommentar)
          --lang de|en   Sprache der Ausgabe (Standard: Systemsprache)

        Umgebungsvariablen: NVD_API_KEY (optionaler NVD-API-Schlüssel), CVESCOUT_LANG (de|en)

        Exit-Code: 0 = nichts gefunden, 1 = Fehler, 2 = Schwachstellen gefunden / CVE betroffen
        """, """
        Usage: cvescout [options]

          --json         print the report as JSON
          --markdown     print the report as Markdown
          --days N       only evaluate BSI advisories from the last N days (default: 730)
          --no-apps      do not check apps in /Applications
          --no-brew      do not check Homebrew packages
          --no-checks    do not check system settings
          --no-nvd       do not use the NVD as a second source
          --refresh      download the BSI feed and KEV catalog again
          --cves FILE    also check a CVE list (text file, one CVE per line, # = comment)
          --lang de|en   output language (default: system language)

        Environment: NVD_API_KEY (optional NVD API key), CVESCOUT_LANG (de|en)

        Exit code: 0 = nothing found, 1 = error, 2 = vulnerabilities found / CVE affected
        """) + "\n\n" + DataSources.attribution
    }

    static func printFinding(_ f: Finding) {
        let kev = f.exploited.isEmpty ? "" : "  🔥 \(f.exploited.count)× " + tr("aktiv ausgenutzt", "actively exploited")
        let score = f.advisory.cvssScore.map { " CVSS \(String(format: "%.1f", $0))" } ?? ""
        print("  [\(f.effectiveSeverity.label.uppercased())] \(f.software.name) \(f.software.version) – "
            + "\(f.advisory.origin.label) \(f.advisory.id)\(score): \(f.advisory.title)\(kev)")
        let fixed = f.fixedVersions.isEmpty ? tr("keine Angabe", "not specified") : f.fixedVersions.joined(separator: ", ")
        print("      " + tr("betroffen", "affected") + ": \(f.matchedRange)  →  " + tr("behoben in", "fixed in") + ": \(fixed)")
    }

    static func main() async {
        let args = Array(CommandLine.arguments.dropFirst())
        if args.contains("-h") || args.contains("--help") {
            print(help)
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
            guard i + 1 < args.count else { fail(tr("--cves erwartet einen Dateipfad.", "--cves expects a file path.")) }
            let path = args[i + 1]
            do {
                let list = try CVEWatchlist.load(from: URL(fileURLWithPath: path))
                guard !list.cves.isEmpty else { fail(tr("Keine CVE-IDs in \(path) gefunden.", "No CVE ids found in \(path).")) }
                options.watchlist = list
            } catch {
                fail(tr("\(path) nicht lesbar: ", "cannot read \(path): ") + error.localizedDescription)
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
                printSummary(report, seconds: Int(Date().timeIntervalSince(start)))
            }
            let cveAffected = report.cveResults?.contains { $0.status == .affected } ?? false
            exit(report.confirmedFindings.isEmpty && !cveAffected ? 0 : 2)
        } catch {
            fail(error.localizedDescription)
        }
    }

    static func printSummary(_ report: ScanReport, seconds: Int) {
        print("\nmacOS \(report.osVersion) · " + tr(
            "\(report.inventory.count) Programme/Pakete · \(report.mappedSoftwareIDs.count) zugeordnet · \(report.advisoriesEvaluated) BSI-Hinweise ausgewertet (\(seconds)s)\n",
            "\(report.inventory.count) apps/packages · \(report.mappedSoftwareIDs.count) mapped · \(report.advisoriesEvaluated) BSI advisories evaluated (\(seconds)s)\n"))

        let confirmed = report.confirmedFindings
        if confirmed.isEmpty {
            print("✅ " + tr("Keine bekannten Schwachstellen gefunden.", "No known vulnerabilities found."))
        } else {
            print("⚠️  " + tr("\(confirmed.count) zutreffende Hinweise für \(report.vulnerableSoftwareCount) Programme:\n",
                             "\(confirmed.count) matching advisories for \(report.vulnerableSoftwareCount) apps:\n"))
            for f in confirmed { printFinding(f) }
        }

        let uncertain = report.uncertainFindings
        if !uncertain.isEmpty {
            print("\n❔ " + tr("\(uncertain.count) unsichere Treffer (bitte manuell prüfen):\n",
                              "\(uncertain.count) uncertain matches (please check manually):\n"))
            for f in uncertain {
                printFinding(f)
                print("      " + tr("Grund", "Reason") + ": \(f.uncertainReason ?? "")")
            }
        }

        if let results = report.cveResults {
            print("\n" + tr("CVE-Liste (\(results.count) Einträge):", "CVE list (\(results.count) entries):"))
            for r in results {
                let icon = switch r.status { case .affected: "❌"; case .patched: "✅"; case .notInstalled: "➖"; case .unknown: "❓" }
                let kev = r.kev == nil ? "" : "  🔥 " + tr("aktiv ausgenutzt", "actively exploited")
                let sw = r.software.isEmpty ? "" : " – \(r.software.joined(separator: ", "))"
                let adv = r.advisories.first.map { " [\($0.id)\(r.advisories.count > 1 ? " +\(r.advisories.count - 1)" : "")]" } ?? ""
                let score = r.cvssScore.map { " (CVSS \(String(format: "%.1f", $0)))" } ?? ""
                print("  \(icon) \(r.cve)\(score): \(r.status.label)\(sw)\(adv)\(kev)")
            }
        }

        if !report.checks.isEmpty {
            print("\n" + tr("Systemprüfungen:", "System checks:"))
            for c in report.checks {
                let icon = switch c.status { case .pass: "✅"; case .warning: "⚠️ "; case .fail: "❌"; case .info: "ℹ️ "; case .error: "❓" }
                print("  \(icon) \(c.title): \(c.detail)")
            }
        }
        if let items = report.persistence {
            let notable = items.filter { $0.assessment != .ok }
            if !notable.isEmpty {
                print("\n" + tr("Autostart-Objekte zum Prüfen:", "Launch items to review:"))
                for i in notable {
                    let icon = i.assessment == .warning ? "⚠️ " : "🔎"
                    print("  \(icon) \(i.label) [\(i.scope.label), \(i.signature.displayName)]: \(i.notes.joined(separator: "; "))")
                }
            }
        }
        if let exts = report.browserExtensions {
            let notable = exts.filter(\.needsReview)
            if !notable.isEmpty {
                print("\n" + tr("Browser-Erweiterungen mit weitreichenden Rechten:", "Browser extensions with powerful permissions:"))
                for e in notable {
                    print("  🔎 \(e.name) \(e.version) (\(e.browser)): \(e.sensitivePermissions.joined(separator: ", "))")
                }
            }
        }
        for w in report.warnings { print(tr("Hinweis", "Note") + ": \(w)") }
    }
}
