import AppKit
import CVEScoutCore
import Foundation
import Observation
import ServiceManagement
import SwiftUI
import UniformTypeIdentifiers
import UserNotifications

@MainActor
@Observable
final class ScanModel {
    var report: ScanReport?
    var isScanning = false
    var phase: ScanPhase?
    var errorMessage: String?
    var watchlist: CVEWatchlist?
    var watchlistFileName: String?
    var sidebarSelection: SidebarItem? = .overview
    /// Changes found by the most recent scan compared to the one before.
    var lastDiff: ReportDiff?
    private var lastAutomaticAttempt: Date?
    private var schedulerTask: Task<Void, Never>?

    // Settings (persisted in UserDefaults)
    var lookbackDays: Int { didSet { defaults.set(lookbackDays, forKey: "lookbackDays") } }
    var includeHomebrew: Bool { didSet { defaults.set(includeHomebrew, forKey: "includeHomebrew") } }
    var includeApplications: Bool { didSet { defaults.set(includeApplications, forKey: "includeApplications") } }
    var useNVD: Bool { didSet { defaults.set(useNVD, forKey: "useNVD") } }
    var nvdAPIKey: String { didSet { Keychain.write("nvd-api-key", value: nvdAPIKey) } }

    /// "system", "de" or "en". Applied at the next launch (see `Language.current`).
    var appLanguage: String {
        didSet {
            if appLanguage == "system" {
                defaults.removeObject(forKey: "appLanguage")
                defaults.removeObject(forKey: "AppleLanguages")
            } else {
                defaults.set(appLanguage, forKey: "appLanguage")
                // Makes AppKit (menus, open/save panels) use the same language as CVEScout.
                defaults.set([appLanguage], forKey: "AppleLanguages")
            }
        }
    }
    private let launchLanguageSetting: String
    var languageChangePending: Bool { appLanguage != launchLanguageSetting }

    // Background operation
    var autoScanInterval: AutoScanInterval {
        didSet { defaults.set(autoScanInterval.rawValue, forKey: "autoScanInterval") }
    }
    var notificationsEnabled: Bool {
        didSet {
            defaults.set(notificationsEnabled, forKey: "notificationsEnabled")
            if notificationsEnabled { Task { await requestNotificationPermission() } }
        }
    }
    var showDockIcon: Bool {
        didSet {
            defaults.set(showDockIcon, forKey: "showDockIcon")
            Self.applyDockPolicy(showDockIcon)
        }
    }
    var launchAtLogin: Bool {
        didSet {
            guard launchAtLogin != (SMAppService.mainApp.status == .enabled) else { return }
            do {
                if launchAtLogin { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            } catch {
                errorMessage = tr("Autostart konnte nicht geändert werden: \(error.localizedDescription)", "Could not change launch at login: \(error.localizedDescription)")
                launchAtLogin = SMAppService.mainApp.status == .enabled
            }
        }
    }

    private let defaults = UserDefaults.standard
    private let scanner = VulnerabilityScanner()

    init() {
        defaults.register(defaults: [
            "lookbackDays": 730, "includeHomebrew": true, "includeApplications": true, "useNVD": true,
            "autoScanInterval": AutoScanInterval.daily.rawValue, "notificationsEnabled": true, "showDockIcon": true,
        ])
        lookbackDays = defaults.integer(forKey: "lookbackDays")
        includeHomebrew = defaults.bool(forKey: "includeHomebrew")
        includeApplications = defaults.bool(forKey: "includeApplications")
        useNVD = defaults.bool(forKey: "useNVD")
        nvdAPIKey = Keychain.read("nvd-api-key") ?? ""
        let language = defaults.string(forKey: "appLanguage") ?? "system"
        appLanguage = language
        launchLanguageSetting = language
        autoScanInterval = AutoScanInterval(rawValue: defaults.integer(forKey: "autoScanInterval")) ?? .daily
        notificationsEnabled = defaults.bool(forKey: "notificationsEnabled")
        showDockIcon = defaults.bool(forKey: "showDockIcon")
        launchAtLogin = SMAppService.mainApp.status == .enabled
        if let cves = defaults.stringArray(forKey: "watchlist"), !cves.isEmpty {
            watchlist = CVEWatchlist(cves: cves)
            watchlistFileName = defaults.string(forKey: "watchlistFileName")
        }
        report = Self.loadLastReport()
        startScheduler()
        if notificationsEnabled { Task { await requestNotificationPermission() } }
    }

    // MARK: Background scheduling

    /// Checks once a minute whether an automatic scan is due. Polling (instead of one long timer)
    /// copes with sleep/wake and with interval changes in the settings.
    private func startScheduler() {
        schedulerTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(60))
                self?.schedulerTick()
            }
        }
    }

    private func schedulerTick() {
        guard !isScanning, autoScanInterval.isDue(lastScan: report?.date) else { return }
        // After a failed attempt (e.g. offline) wait 15 minutes before trying again.
        if let last = lastAutomaticAttempt, Date().timeIntervalSince(last) < 15 * 60 { return }
        lastAutomaticAttempt = Date()
        startScan(automatic: true)
    }

    var nextAutomaticScan: Date? {
        guard let interval = autoScanInterval.interval else { return nil }
        return (report?.date ?? Date()).addingTimeInterval(interval)
    }

    // MARK: Status for the menu bar

    var statusSymbol: String {
        if isScanning { return "shield.lefthalf.filled" }
        guard let report else { return "shield" }
        if report.exploitedCount > 0 { return "xmark.shield.fill" }
        if !report.confirmedFindings.isEmpty || report.checks.contains(where: { $0.status == .fail }) {
            return "exclamationmark.shield.fill"
        }
        return "checkmark.shield.fill"
    }

    var statusColor: Color {
        guard let report, !isScanning else { return .secondary }
        if report.exploitedCount > 0 || report.checks.contains(where: { $0.status == .fail }) { return .red }
        if !report.confirmedFindings.isEmpty { return .orange }
        return .green
    }

    var statusHeadline: String {
        if isScanning { return tr("Scan läuft …", "Scanning …") }
        guard let report else { return tr("Noch kein Scan", "No scan yet") }
        if report.exploitedCount > 0 { return tr("Aktiv ausgenutzte Lücke!", "Actively exploited vulnerability!") }
        let n = report.vulnerableSoftwareCount
        if n > 0 { return n == 1 ? tr("1 Programm verwundbar", "1 app vulnerable") : tr("\(n) Programme verwundbar", "\(n) apps vulnerable") }
        if report.checks.contains(where: { $0.status == .fail }) { return tr("Einstellung kritisch", "Critical setting") }
        return tr("Keine bekannten Lücken", "No known vulnerabilities")
    }

    /// Quits and reopens the app (used after changing the language).
    func relaunch() {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "sleep 1; /usr/bin/open \"$0\"", Bundle.main.bundleURL.path]
        try? process.run()
        NSApp.terminate(nil)
    }

    // MARK: Window & Dock

    static func applyDockPolicy(_ visible: Bool) {
        NSApp?.setActivationPolicy(visible ? .regular : .accessory)
    }

    // MARK: Notifications

    /// UNUserNotificationCenter needs a real app bundle (not available under `swift run`).
    static var canNotify: Bool { Bundle.main.bundleURL.pathExtension == "app" }

    func requestNotificationPermission() async {
        guard Self.canNotify else { return }
        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
    }

    private func notify(_ diff: ReportDiff) {
        guard Self.canNotify, notificationsEnabled, let text = diff.notificationText else { return }
        let content = UNMutableNotificationContent()
        content.title = text.title
        content.body = text.body
        content.sound = .default
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        Task { try? await UNUserNotificationCenter.current().add(request) }
    }

    // MARK: Scanning

    func startScan(forceRefresh: Bool = false, automatic: Bool = false) {
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
                let diff = ReportDiff(current: report, previous: self.report)
                self.lastDiff = diff
                self.report = report
                Self.saveLastReport(report)
                if automatic { self.notify(diff) }
            } catch {
                // Automatic scans fail silently (e.g. offline); the scheduler retries later.
                if !automatic { self.errorMessage = tr("Scan fehlgeschlagen: \(error.localizedDescription)", "Scan failed: \(error.localizedDescription)") }
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
                errorMessage = tr("In „\(url.lastPathComponent)“ wurde keine CVE-ID gefunden (erwartet: eine CVE pro Zeile).", "No CVE id found in “\(url.lastPathComponent)” (expected: one CVE per line).")
                return
            }
            watchlist = list
            watchlistFileName = url.lastPathComponent
            defaults.set(list.cves, forKey: "watchlist")
            defaults.set(url.lastPathComponent, forKey: "watchlistFileName")
            if !list.invalidLines.isEmpty {
                errorMessage = tr("\(list.invalidLines.count) Zeilen ohne CVE-ID wurden ignoriert.", "\(list.invalidLines.count) lines without a CVE id were ignored.")
            }
            startScan()
        } catch {
            errorMessage = tr("Datei konnte nicht gelesen werden: \(error.localizedDescription)", "Could not read the file: \(error.localizedDescription)")
        }
    }

    func importWatchlistWithPanel() {
        let panel = NSOpenPanel()
        panel.title = tr("CVE-Liste importieren", "Import CVE list")
        panel.message = tr("Textdatei mit einer CVE-ID pro Zeile auswählen", "Choose a text file with one CVE id per line")
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
        panel.nameFieldStringValue = tr("CVEScout-Bericht", "CVEScout-Report") + "-\(stamp)." + (markdown ? "md" : "json")
        panel.allowedContentTypes = [markdown ? UTType(filenameExtension: "md") ?? .plainText : .json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data = markdown ? Data(ReportExport.markdown(report).utf8) : try ReportExport.json(report)
            try data.write(to: url, options: .atomic)
        } catch {
            errorMessage = tr("Export fehlgeschlagen: \(error.localizedDescription)", "Export failed: \(error.localizedDescription)")
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
