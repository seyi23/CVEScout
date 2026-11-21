import Foundation

/// Fictitious example report for screenshots and demos (`CVESCOUT_DEMO=1`).
/// All advisory ids and CVE numbers are placeholders and do not refer to real advisories.
public enum DemoData {
    public static var isEnabled: Bool { ProcessInfo.processInfo.environment["CVESCOUT_DEMO"] == "1" }

    public static func report(now: Date = Date()) -> ScanReport {
        func app(_ name: String, _ id: String, _ version: String, _ source: SoftwareSource = .application) -> SoftwareItem {
            SoftwareItem(name: name, identifier: id, version: version, source: source,
                         path: source == .application ? "/Applications/\(name).app" : nil)
        }
        let macOS = app("macOS", "macos", "27.2", .system)
        let chrome = app("Google Chrome", "com.google.Chrome", "141.0.7390.54")
        let firefox = app("Firefox", "org.mozilla.firefox", "152.0")
        let vlc = app("VLC", "org.videolan.vlc", "3.0.20")
        let discord = app("Discord", "com.hnc.Discord", "0.0.390")
        let openssl = app("openssl@3", "openssl@3", "3.5.1", .homebrew)
        let ffmpeg = app("ffmpeg", "ffmpeg", "8.0", .homebrew)
        let inventory = [macOS, chrome, firefox, vlc, discord, openssl, ffmpeg,
                         app("Zoom", "us.zoom.xos", "6.5.2"), app("1Password", "com.1password.1password", "8.11.4"),
                         app("Visual Studio Code", "com.microsoft.VSCode", "1.104.0"), app("git", "git", "2.51.0", .homebrew)]

        let url = URL(string: "https://example.org/cvescout-demo")!
        func advisory(_ n: Int, _ title: String, _ severity: Severity, cves: Int, source: AdvisorySource = .bsi,
                      score: Double? = nil, daysAgo: Double) -> Advisory {
            Advisory(id: source == .bsi ? "WID-SEC-W-2026-DEMO\(n)" : "CVE-2026-9000\(n)", title: title, severity: severity,
                     published: now.addingTimeInterval(-86_400 * (daysAgo + 2)), updated: now.addingTimeInterval(-86_400 * daysAgo),
                     summary: tr("Ein entfernter, anonymer Angreifer kann mehrere Schwachstellen ausnutzen, um beliebigen Programmcode auszuführen.",
                                 "A remote, anonymous attacker can exploit several vulnerabilities to execute arbitrary code."),
                     csafURL: url, portalURL: url,
                     cves: (1...cves).map { "CVE-2026-\(1000 + n * 10 + $0)" }, source: source, cvssScore: score)
        }
        let kev = KEVEntry(cveID: "CVE-2026-1011", vendorProject: "Google", product: "Chromium V8",
                           vulnerabilityName: "Google Chromium V8 Type Confusion Vulnerability", dateAdded: "2026-11-12",
                           shortDescription: "Type confusion in V8 allows a remote attacker to execute code via a crafted HTML page.",
                           requiredAction: "Apply mitigations per vendor instructions.", knownRansomwareCampaignUse: "Unknown")

        let findings: [Finding] = [
            Finding(software: chrome, advisory: advisory(1, "Google Chrome: Mehrere Schwachstellen", .high, cves: 6, daysAgo: 3),
                    product: ProductRef("Google", "Chrome"), matchedRange: "Google Chrome <142.0.7444.59",
                    fixedVersions: ["142.0.7444.59"], exploited: [kev], confidence: .curated),
            Finding(software: firefox, advisory: advisory(2, "Mozilla Firefox und Thunderbird: Mehrere Schwachstellen", .high, cves: 9, daysAgo: 6),
                    product: ProductRef("Mozilla", "Firefox"), matchedRange: "Mozilla Firefox <153",
                    fixedVersions: ["153"], exploited: [], confidence: .curated),
            Finding(software: openssl, advisory: advisory(3, "OpenSSL: Mehrere Schwachstellen", .high, cves: 3, daysAgo: 12),
                    product: ProductRef("Open Source", "OpenSSL"), matchedRange: "Open Source OpenSSL <3.5.4",
                    fixedVersions: ["3.0.18", "3.4.3", "3.5.4"], exploited: [], confidence: .curated),
            Finding(software: discord,
                    advisory: advisory(4, "Discord desktop before 0.0.400 allows remote code execution via crafted invite links",
                                       .medium, cves: 1, source: .nvd, score: 6.8, daysAgo: 20),
                    product: ProductRef("discord", "discord"), matchedRange: "discord:discord <0.0.400",
                    fixedVersions: ["0.0.400"], exploited: [], confidence: .cpe),
            Finding(software: vlc, advisory: advisory(5, "VLC: Schwachstelle ermöglicht Codeausführung", .medium, cves: 1, daysAgo: 40),
                    product: ProductRef("Open Source", "VLC"), matchedRange: "Open Source VLC <3.0.21",
                    fixedVersions: ["3.0.21"], exploited: [], confidence: .curated),
            Finding(software: ffmpeg, advisory: advisory(6, "ffmpeg: Mehrere Schwachstellen", .medium, cves: 4, daysAgo: 30),
                    product: ProductRef("Open Source", "ffmpeg"), matchedRange: "Open Source ffmpeg >=7.0",
                    fixedVersions: [], exploited: [], confidence: .heuristic,
                    uncertainReason: tr("Der Hinweis nennt keine behobene Version – die Angabe lässt sich nicht überprüfen.",
                                        "The advisory names no fixed version – the claim cannot be verified.")),
        ]

        let checks: [SecurityCheckResult] = [
            .init(id: "sip", title: "System Integrity Protection (SIP)", status: .pass, detail: tr("SIP ist aktiviert.", "SIP is enabled.")),
            .init(id: "gatekeeper", title: "Gatekeeper", status: .pass, detail: tr("Gatekeeper prüft Programme vor dem Start.", "Gatekeeper checks apps before they launch.")),
            .init(id: "filevault", title: tr("FileVault-Verschlüsselung", "FileVault encryption"), status: .pass,
                  detail: tr("Das Startvolume ist verschlüsselt.", "The startup volume is encrypted.")),
            .init(id: "firewall", title: "Firewall", status: .warning, detail: "Firewall is disabled. (State = 0)",
                  recommendation: tr("Firewall unter Systemeinstellungen › Netzwerk › Firewall einschalten.",
                                     "Turn on the firewall in System Settings › Network › Firewall.")),
            .init(id: "pending-updates", title: tr("Ausstehende Apple-Updates", "Pending Apple updates"), status: .fail,
                  detail: "macOS 27.2.1", recommendation: tr("Updates unter Systemeinstellungen › Allgemein › Softwareupdate installieren.",
                                                             "Install the updates in System Settings › General › Software Update.")),
            .init(id: "ports", title: tr("Offene Netzwerkdienste", "Exposed network services"), status: .pass,
                  detail: tr("Keine Dienste lauschen im Netzwerk.", "No services are listening on the network.")),
            .init(id: "xprotect", title: tr("XProtect-Malware-Signaturen", "XProtect malware signatures"), status: .pass,
                  detail: "Version 5400"),
            .init(id: "persistence", title: tr("Autostart-Objekte (launchd)", "Launch items (launchd)"), status: .warning,
                  detail: tr("6 Einträge, 1 auffällig: com.example.updater", "6 entries, 1 suspicious: com.example.updater")),
        ]

        func item(_ label: String, _ scope: PersistenceItem.Scope, _ program: String, _ kind: SignatureKind,
                  _ signer: String?, _ assessment: PersistenceItem.Assessment, _ notes: [String], script: String? = nil) -> PersistenceItem {
            PersistenceItem(label: label, plistPath: "/Library/LaunchDaemons/\(label).plist", scope: scope, program: program,
                            arguments: script.map { [$0] } ?? [], runAtLoad: true, disabled: false,
                            signature: CodeSignature(kind: kind, signer: signer, teamID: nil), scriptPath: script,
                            assessment: assessment, notes: notes)
        }
        let persistence = [
            item("com.example.updater", .systemDaemon, "/Library/Application Support/Example/updater", .unsigned, nil, .warning,
                 [tr("Programm ist nicht signiert", "program is unsigned")]),
            item("com.example.sync", .userAgent, "/bin/zsh", .apple, "Software Signing", .review,
                 [tr("startet ein Skript über zsh", "runs a script via zsh")], script: "/Users/Shared/sync.sh"),
            item("com.oldvendor.helper", .systemAgent, "/Applications/OldTool.app/Contents/MacOS/helper", .missing, nil, .review,
                 [tr("Programm existiert nicht mehr (verwaister Eintrag)", "program no longer exists (orphaned entry)")]),
            item("com.google.keystone.agent", .userAgent, "/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdateAgent",
                 .developerID, "Developer ID Application: Google LLC (EQHXZ8M8AV)", .ok, []),
            item("com.microsoft.update.agent", .systemAgent, "/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app",
                 .developerID, "Developer ID Application: Microsoft Corporation (UBF8T346G9)", .ok, []),
            item("us.zoom.ZoomDaemon", .systemDaemon, "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon",
                 .developerID, "Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)", .ok, []),
        ]

        func ext(_ browser: String, _ name: String, _ version: String, broad: Bool, _ perms: [String]) -> BrowserExtension {
            BrowserExtension(browser: browser, profile: "Default", extensionID: name.lowercased().filter(\.isLetter),
                             name: name, version: version, broadAccess: broad, sensitivePermissions: perms, enabled: true)
        }
        let extensions = [
            ext("Google Chrome", "Coupon Helper Pro", "2.4.1", broad: true, ["cookies", "nativeMessaging", "webRequest"]),
            ext("Google Chrome", "uBlock Origin Lite", "2025.1102", broad: true, []),
            ext("Google Chrome", "1Password", "8.11.4", broad: true, []),
            ext("Firefox", "Dark Reader", "4.9.110", broad: true, []),
            ext("Safari", "Grammar Checker", "1.3.0", broad: false, []),
        ]

        let cveResults = [
            CVECheckResult(cve: "CVE-2026-1011", status: .affected, advisories: [.init(id: "WID-SEC-W-2026-DEMO1", title: "", url: url)],
                           software: ["Google Chrome 141.0.7390.54"], matchedRanges: ["Google Chrome <142.0.7444.59"], kev: kev),
            CVECheckResult(cve: "CVE-2024-3094", status: .notInstalled, advisories: [.init(id: "WID-SEC-W-2024-0762", title: "", url: url)],
                           software: [], matchedRanges: [], kev: nil),
            CVECheckResult(cve: "CVE-2024-6387", status: .patched, advisories: [.init(id: "WID-SEC-W-2024-1486", title: "", url: url)],
                           software: ["macOS 27.2"], matchedRanges: [], kev: nil),
            CVECheckResult(cve: "CVE-2026-90001", status: .unknown, advisories: [], software: [], matchedRanges: [], kev: nil),
        ]

        return ScanReport(
            date: now.addingTimeInterval(-25 * 60), osVersion: macOS.version, inventory: inventory, findings: findings,
            checks: checks, mappedSoftwareIDs: inventory.prefix(9).map(\.id), advisoriesEvaluated: 512,
            bsiFeedDate: now.addingTimeInterval(-3600), kevCatalogVersion: "2026.11.20", warnings: [],
            cveResults: cveResults, persistence: persistence, browserExtensions: extensions
        )
    }
}
