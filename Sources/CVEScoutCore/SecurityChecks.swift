import Foundation

/// Read-only checks of the local macOS security configuration.
/// None of them changes a setting or needs administrator rights.
public enum SecurityChecks {
    public static func runAll() async -> [SecurityCheckResult] {
        async let sip = systemIntegrityProtection()
        async let gatekeeper = gatekeeper()
        async let fileVault = fileVault()
        async let firewall = firewall()
        async let ports = listeningServices()
        async let pending = pendingUpdates()
        let sync = [automaticUpdates(), xprotect(), automaticLogin(), guestAccount()]
        return await [sip, gatekeeper, fileVault] + firewall + [ports, pending] + sync
    }

    // MARK: - Individual checks

    static func systemIntegrityProtection() async -> SecurityCheckResult {
        let title = "System Integrity Protection (SIP)"
        guard let r = await Shell.run("/usr/bin/csrutil", ["status"]) else {
            return .init(id: "sip", title: title, status: .error, detail: tr("csrutil konnte nicht ausgeführt werden.", "Could not run csrutil."))
        }
        if r.output.contains("status: enabled") {
            return .init(id: "sip", title: title, status: .pass, detail: tr("SIP ist aktiviert.", "SIP is enabled."))
        }
        return .init(id: "sip", title: title, status: .fail, detail: r.output,
                     recommendation: tr("SIP im Wiederherstellungsmodus mit `csrutil enable` wieder aktivieren.", "Re-enable SIP from Recovery mode with `csrutil enable`."))
    }

    static func gatekeeper() async -> SecurityCheckResult {
        let title = "Gatekeeper"
        guard let r = await Shell.run("/usr/sbin/spctl", ["--status"]) else {
            return .init(id: "gatekeeper", title: title, status: .error, detail: tr("spctl konnte nicht ausgeführt werden.", "Could not run spctl."))
        }
        if r.output.contains("assessments enabled") {
            return .init(id: "gatekeeper", title: title, status: .pass, detail: tr("Gatekeeper prüft Programme vor dem Start.", "Gatekeeper checks apps before they launch."))
        }
        return .init(id: "gatekeeper", title: title, status: .fail, detail: r.output,
                     recommendation: tr("Gatekeeper wieder aktivieren: `sudo spctl --global-enable`.", "Re-enable Gatekeeper: `sudo spctl --global-enable`."))
    }

    static func fileVault() async -> SecurityCheckResult {
        let title = tr("FileVault-Verschlüsselung", "FileVault encryption")
        guard let r = await Shell.run("/usr/bin/fdesetup", ["status"]) else {
            return .init(id: "filevault", title: title, status: .error, detail: tr("fdesetup konnte nicht ausgeführt werden.", "Could not run fdesetup."))
        }
        if r.output.contains("FileVault is On") {
            return .init(id: "filevault", title: title, status: .pass, detail: tr("Das Startvolume ist verschlüsselt.", "The startup volume is encrypted."))
        }
        if r.output.contains("in progress") {
            return .init(id: "filevault", title: title, status: .warning, detail: r.output)
        }
        return .init(id: "filevault", title: title, status: .fail, detail: r.output,
                     recommendation: tr("FileVault unter Systemeinstellungen › Datenschutz & Sicherheit aktivieren.", "Turn on FileVault in System Settings › Privacy & Security."))
    }

    static func firewall() async -> [SecurityCheckResult] {
        let tool = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        async let globalState = Shell.run(tool, ["--getglobalstate"])
        async let stealthState = Shell.run(tool, ["--getstealthmode"])
        let (global, stealth) = await (globalState, stealthState)

        let fw: SecurityCheckResult
        if let global, global.output.contains("enabled") {
            fw = .init(id: "firewall", title: "Firewall", status: .pass, detail: tr("Die Programm-Firewall ist aktiv.", "The application firewall is on."))
        } else if let global {
            fw = .init(id: "firewall", title: "Firewall", status: .warning, detail: global.output,
                       recommendation: tr("Firewall unter Systemeinstellungen › Netzwerk › Firewall einschalten.", "Turn on the firewall in System Settings › Network › Firewall."))
        } else {
            fw = .init(id: "firewall", title: "Firewall", status: .error, detail: tr("socketfilterfw konnte nicht ausgeführt werden.", "Could not run socketfilterfw."))
        }

        let st: SecurityCheckResult
        if let stealth, stealth.output.localizedCaseInsensitiveContains("stealth mode enabled")
            || stealth.output.contains("is on") {
            st = .init(id: "stealth", title: tr("Tarnmodus (Stealth Mode)", "Stealth mode"), status: .pass, detail: tr("Der Mac antwortet nicht auf Ping/Port-Scans.", "The Mac does not respond to ping or port scans."))
        } else {
            st = .init(id: "stealth", title: tr("Tarnmodus (Stealth Mode)", "Stealth mode"), status: .info,
                       detail: stealth?.output ?? tr("Status unbekannt.", "Status unknown."),
                       recommendation: tr("Optional: Tarnmodus in den Firewall-Optionen aktivieren.", "Optional: turn on stealth mode in the firewall options."))
        }
        return [fw, st]
    }

    /// Services listening on non-loopback addresses (Remote Login, Screen Sharing, File Sharing …).
    static func listeningServices() async -> SecurityCheckResult {
        let title = tr("Offene Netzwerkdienste", "Exposed network services")
        guard let r = await Shell.run("/usr/sbin/netstat", ["-an", "-p", "tcp"]) else {
            return .init(id: "ports", title: title, status: .error, detail: tr("netstat konnte nicht ausgeführt werden.", "Could not run netstat."))
        }
        let exposed = parseListeningPorts(r.output)
        let risky: [Int: String] = [
            22: tr("SSH / Entfernte Anmeldung", "SSH / Remote Login"), 5900: tr("Bildschirmfreigabe (VNC)", "Screen Sharing (VNC)"), 3283: "Apple Remote Desktop",
            445: tr("Dateifreigabe (SMB)", "File Sharing (SMB)"), 548: tr("Dateifreigabe (AFP)", "File Sharing (AFP)"), 21: "FTP", 23: "Telnet",
        ]
        let riskyOpen = exposed.filter { risky[$0] != nil }.sorted()
        let all = exposed.sorted().map(String.init).joined(separator: ", ")
        if riskyOpen.isEmpty {
            return .init(id: "ports", title: title, status: exposed.isEmpty ? .pass : .info,
                         detail: exposed.isEmpty ? tr("Keine Dienste lauschen im Netzwerk.", "No services are listening on the network.")
                                                 : tr("Im Netzwerk erreichbare Ports: \(all)", "Ports reachable from the network: \(all)"))
        }
        let names = riskyOpen.map { "\($0) (\(risky[$0]!))" }.joined(separator: ", ")
        return .init(id: "ports", title: title, status: .warning,
                     detail: tr("Fernzugriffsdienste erreichbar: \(names). Alle Ports: \(all)", "Remote access services reachable: \(names). All ports: \(all)"),
                     recommendation: tr("Nicht benötigte Freigaben unter Systemeinstellungen › Allgemein › Teilen deaktivieren.", "Turn off unneeded sharing services in System Settings › General › Sharing."))
    }

    /// Parses `netstat -an -p tcp` output and returns ports in LISTEN state bound to non-loopback addresses.
    public static func parseListeningPorts(_ output: String) -> Set<Int> {
        var ports = Set<Int>()
        for line in output.split(separator: "\n") where line.contains("LISTEN") {
            let cols = line.split(separator: " ", omittingEmptySubsequences: true)
            guard cols.count >= 4 else { continue }
            let local = String(cols[3])
            guard let dot = local.lastIndex(of: "."), let port = Int(local[local.index(after: dot)...]) else { continue }
            let host = String(local[..<dot])
            if host.hasPrefix("127.") || host == "::1" || host.hasPrefix("fe80::1%lo0") { continue }
            ports.insert(port)
        }
        return ports
    }

    /// Asks Apple's update server for pending updates (`softwareupdate --list`, no admin rights needed).
    static func pendingUpdates() async -> SecurityCheckResult {
        let title = tr("Ausstehende Apple-Updates", "Pending Apple updates")
        guard let r = await Shell.run("/usr/sbin/softwareupdate", ["--list"], timeout: 120), !r.timedOut else {
            return .init(id: "pending-updates", title: title, status: .error,
                         detail: tr("softwareupdate hat nicht rechtzeitig geantwortet (offline?).", "softwareupdate did not respond in time (offline?)."))
        }
        let updates = parsePendingUpdates(r.output)
        if updates.isEmpty {
            if r.output.contains("No new software available") {
                return .init(id: "pending-updates", title: title, status: .pass, detail: tr("Keine ausstehenden Updates.", "No pending updates."))
            }
            return .init(id: "pending-updates", title: title, status: .info, detail: r.output)
        }
        let critical = updates.contains { u in
            let t = u.lowercased()
            return t.contains("macos") || t.contains("security") || t.contains("sicherheit") || t.contains("safari")
        }
        return .init(id: "pending-updates", title: title, status: critical ? .fail : .warning,
                     detail: updates.joined(separator: "; "),
                     recommendation: tr("Updates unter Systemeinstellungen › Allgemein › Softwareupdate installieren.", "Install the updates in System Settings › General › Software Update."))
    }

    /// Extracts "Title (Version)" for each pending update from `softwareupdate --list` output.
    public static func parsePendingUpdates(_ output: String) -> [String] {
        output.split(separator: "\n").compactMap { raw in
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("Title:") else { return nil }
            var fields: [String: String] = [:]
            for part in line.split(separator: ",") {
                let kv = part.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                if kv.count == 2 { fields[kv[0]] = kv[1] }
            }
            guard let title = fields["Title"] else { return nil }
            if let version = fields["Version"], !title.contains(version) { return "\(title) (\(version))" }
            return title
        }
    }

    static func automaticUpdates() -> SecurityCheckResult {
        let title = tr("Automatische Updates", "Automatic updates")
        let prefs = NSDictionary(contentsOfFile: "/Library/Preferences/com.apple.SoftwareUpdate.plist") as? [String: Any] ?? [:]
        let keys: [(String, String)] = [
            ("AutomaticCheckEnabled", tr("Nach Updates suchen", "Check for updates")),
            ("AutomaticDownload", tr("Updates laden", "Download updates")),
            ("CriticalUpdateInstall", tr("Sicherheitsmaßnahmen und Systemdateien installieren", "Install Security Responses and system files")),
            ("ConfigDataInstall", tr("XProtect-/Konfigurationsdaten installieren", "Install XProtect/configuration data")),
            ("AutomaticallyInstallMacOSUpdates", tr("macOS-Updates installieren", "Install macOS updates")),
        ]
        var off: [String] = []
        var securityOff = false
        for (key, label) in keys {
            let disabled = (prefs[key] as? Bool) == false || (prefs[key] as? Int) == 0
            guard disabled else { continue }
            off.append(label)
            if key == "CriticalUpdateInstall" || key == "ConfigDataInstall" { securityOff = true }
        }
        if off.isEmpty {
            return .init(id: "updates", title: title, status: .pass,
                         detail: tr("Keine automatische Update-Option ist explizit deaktiviert.", "No automatic update option is explicitly turned off."))
        }
        return .init(id: "updates", title: title, status: securityOff ? .fail : .warning,
                     detail: tr("Deaktiviert: ", "Turned off: ") + off.joined(separator: ", "),
                     recommendation: tr("Unter Systemeinstellungen › Allgemein › Softwareupdate › Automatische Updates alle Optionen einschalten.", "Turn on all options in System Settings › General › Software Update › Automatic Updates."))
    }

    static func xprotect() -> SecurityCheckResult {
        let title = tr("XProtect-Malware-Signaturen", "XProtect malware signatures")
        let path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle"
        let plist = NSDictionary(contentsOfFile: path + "/Contents/Info.plist") as? [String: Any]
        guard let version = plist?["CFBundleShortVersionString"] as? String else {
            return .init(id: "xprotect", title: title, status: .info, detail: tr("XProtect-Version nicht lesbar.", "Could not read the XProtect version."))
        }
        let modified = (try? FileManager.default.attributesOfItem(atPath: path + "/Contents/Info.plist"))?[.modificationDate] as? Date
        guard let modified else {
            return .init(id: "xprotect", title: title, status: .info, detail: "Version \(version)")
        }
        let days = Int(Date().timeIntervalSince(modified) / 86_400)
        let date = modified.formatted(Date.FormatStyle(date: .abbreviated, time: .omitted).locale(Language.current.locale))
        if days > 90 {
            return .init(id: "xprotect", title: title, status: .warning,
                         detail: tr("Version \(version), zuletzt aktualisiert am \(date) (vor \(days) Tagen).", "Version \(version), last updated on \(date) (\(days) days ago)."),
                         recommendation: tr("Automatische Installation von Sicherheitsdaten aktivieren und nach Updates suchen.", "Turn on automatic installation of security data and check for updates."))
        }
        return .init(id: "xprotect", title: title, status: .pass,
                     detail: tr("Version \(version), aktualisiert am \(date).", "Version \(version), updated on \(date)."))
    }

    static func automaticLogin() -> SecurityCheckResult {
        let title = tr("Automatische Anmeldung", "Automatic login")
        let prefs = NSDictionary(contentsOfFile: "/Library/Preferences/com.apple.loginwindow.plist") as? [String: Any]
        if let user = prefs?["autoLoginUser"] as? String, !user.isEmpty {
            return .init(id: "autologin", title: title, status: .fail,
                         detail: tr("Benutzer wird ohne Passwort angemeldet.", "A user is logged in without a password."),
                         recommendation: tr("Unter Systemeinstellungen › Benutzer:innen & Gruppen die automatische Anmeldung ausschalten.", "Turn off automatic login in System Settings › Users & Groups."))
        }
        return .init(id: "autologin", title: title, status: .pass, detail: tr("Automatische Anmeldung ist aus.", "Automatic login is off."))
    }

    static func guestAccount() -> SecurityCheckResult {
        let title = tr("Gastbenutzer", "Guest user")
        let prefs = NSDictionary(contentsOfFile: "/Library/Preferences/com.apple.loginwindow.plist") as? [String: Any]
        if (prefs?["GuestEnabled"] as? Bool) == true {
            return .init(id: "guest", title: title, status: .warning, detail: tr("Der Gastbenutzer ist aktiviert.", "The guest user is enabled."),
                         recommendation: tr("Gastbenutzer unter Systemeinstellungen › Benutzer:innen & Gruppen deaktivieren.", "Turn off the guest user in System Settings › Users & Groups."))
        }
        return .init(id: "guest", title: title, status: .pass, detail: tr("Gastbenutzer ist deaktiviert.", "The guest user is disabled."))
    }
}
