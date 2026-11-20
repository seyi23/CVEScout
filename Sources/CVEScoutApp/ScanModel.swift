import AppKit
import CVEScoutCore
import Foundation
import Observation
import UniformTypeIdentifiers

@MainActor
@Observable
final class ScanModel {
    var report: ScanReport?
    var isScanning = false
    var phase: ScanPhase?
    var errorMessage: String?
    var watchlist: CVEWatchlist?
    var watchlistFileName: String?

    // Settings (persisted in UserDefaults)
    var lookbackDays: Int { didSet { defaults.set(lookbackDays, forKey: "lookbackDays") } }
    var includeHomebrew: Bool { didSet { defaults.set(includeHomebrew, forKey: "includeHomebrew") } }
    var includeApplications: Bool { didSet { defaults.set(includeApplications, forKey: "includeApplications") } }
    var useNVD: Bool { didSet { defaults.set(useNVD, forKey: "useNVD") } }
    var nvdAPIKey: String { didSet { Keychain.write("nvd-api-key", value: nvdAPIKey) } }

    private let defaults = UserDefaults.standard
    private let scanner = VulnerabilityScanner()

    init() {
        defaults.register(defaults: ["lookbackDays": 730, "includeHomebrew": true, "includeApplications": true, "useNVD": true])
        lookbackDays = defaults.integer(forKey: "lookbackDays")
        includeHomebrew = defaults.bool(forKey: "includeHomebrew")
        includeApplications = defaults.bool(forKey: "includeApplications")
        useNVD = defaults.bool(forKey: "useNVD")
        nvdAPIKey = Keychain.read("nvd-api-key") ?? ""
        if let cves = defaults.stringArray(forKey: "watchlist"), !cves.isEmpty {
            watchlist = CVEWatchlist(cves: cves)
            watchlistFileName = defaults.string(forKey: "watchlistFileName")
        }
        report = Self.loadLastReport()
    }

    // MARK: Scanning

    func startScan(forceRefresh: Bool = false) {
        guard !isScanning else { return }
        isScanning = true
        errorMessage = nil
        phase = .inventory
        var options = ScanOptions()
        options.lookbackDays = lookbackDays
        options.includeHomebrew = includeHomebrew
        options.includeApplications = includeApplications
        options.forceRefresh = forceRefresh
        options.watchlist = watchlist
        options.useNVD = useNVD
        options.nvdAPIKey = nvdAPIKey.isEmpty ? nil : nvdAPIKey
        let scanner = self.scanner
        Task {
            do {
                let report = try await scanner.run(options: options) { phase in
                    Task { @MainActor in self.phase = phase }
                }
                self.report = report
                Self.saveLastReport(report)
            } catch {
                self.errorMessage = "Scan fehlgeschlagen: \(error.localizedDescription)"
            }
            self.isScanning = false
            self.phase = nil
        }
    }

    // MARK: CVE list

    func importWatchlist(from url: URL) {
        let accessing = url.startAccessingSecurityScopedResource()
        defer { if accessing { url.stopAccessingSecurityScopedResource() } }
        do {
            let list = try CVEWatchlist.load(from: url)
            guard !list.cves.isEmpty else {
                errorMessage = "In „\(url.lastPathComponent)“ wurde keine CVE-ID gefunden (erwartet: eine CVE pro Zeile)."
                return
            }
            watchlist = list
            watchlistFileName = url.lastPathComponent
            defaults.set(list.cves, forKey: "watchlist")
            defaults.set(url.lastPathComponent, forKey: "watchlistFileName")
            if !list.invalidLines.isEmpty {
                errorMessage = "\(list.invalidLines.count) Zeilen ohne CVE-ID wurden ignoriert."
            }
            startScan()
        } catch {
            errorMessage = "Datei konnte nicht gelesen werden: \(error.localizedDescription)"
        }
    }

    func importWatchlistWithPanel() {
        let panel = NSOpenPanel()
        panel.title = "CVE-Liste importieren"
        panel.message = "Textdatei mit einer CVE-ID pro Zeile auswählen"
        panel.allowedContentTypes = [.plainText, .text]
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url { importWatchlist(from: url) }
    }

    func clearWatchlist() {
        watchlist = nil
        watchlistFileName = nil
        defaults.removeObject(forKey: "watchlist")
        defaults.removeObject(forKey: "watchlistFileName")
    }

    // MARK: Export

    func export(markdown: Bool) {
        guard let report else { return }
        let panel = NSSavePanel()
        let stamp = report.date.formatted(.iso8601.year().month().day())
        panel.nameFieldStringValue = "CVEScout-Bericht-\(stamp).\(markdown ? "md" : "json")"
        panel.allowedContentTypes = [markdown ? UTType(filenameExtension: "md") ?? .plainText : .json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data = markdown ? Data(ReportExport.markdown(report).utf8) : try ReportExport.json(report)
            try data.write(to: url, options: .atomic)
        } catch {
            errorMessage = "Export fehlgeschlagen: \(error.localizedDescription)"
        }
    }

    // MARK: Persistence

    private static var reportURL: URL {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("CVEScout", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("last-report.json")
    }

    private static func saveLastReport(_ report: ScanReport) {
        try? ReportExport.json(report).write(to: reportURL, options: .atomic)
    }

    private static func loadLastReport() -> ScanReport? {
        guard let data = try? Data(contentsOf: reportURL) else { return nil }
        return try? ReportExport.decodeJSON(data)
    }
}
