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
            return .init(id: "sip", title: title, status: .error, detail: "csrutil konnte nicht ausgeführt werden.")
        }
        if r.output.contains("status: enabled") {
            return .init(id: "sip", title: title, status: .pass, detail: "SIP ist aktiviert.")
        }
        return .init(id: "sip", title: title, status: .fail, detail: r.output,
                     recommendation: "SIP im Wiederherstellungsmodus mit `csrutil enable` wieder aktivieren.")
    }

    static func gatekeeper() async -> SecurityCheckResult {
        let title = "Gatekeeper"
        guard let r = await Shell.run("/usr/sbin/spctl", ["--status"]) else {
            return .init(id: "gatekeeper", title: title, status: .error, detail: "spctl konnte nicht ausgeführt werden.")
        }
        if r.output.contains("assessments enabled") {
            return .init(id: "gatekeeper", title: title, status: .pass, detail: "Gatekeeper prüft Programme vor dem Start.")
        }
        return .init(id: "gatekeeper", title: title, status: .fail, detail: r.output,
                     recommendation: "Gatekeeper wieder aktivieren: `sudo spctl --global-enable`.")
    }

    static func fileVault() async -> SecurityCheckResult {
        let title = "FileVault-Verschlüsselung"
        guard let r = await Shell.run("/usr/bin/fdesetup", ["status"]) else {
            return .init(id: "filevault", title: title, status: .error, detail: "fdesetup konnte nicht ausgeführt werden.")
        }
        if r.output.contains("FileVault is On") {
            return .init(id: "filevault", title: title, status: .pass, detail: "Das Startvolume ist verschlüsselt.")
        }
        if r.output.contains("in progress") {
            return .init(id: "filevault", title: title, status: .warning, detail: r.output)
        }
        return .init(id: "filevault", title: title, status: .fail, detail: r.output,
                     recommendation: "FileVault unter Systemeinstellungen › Datenschutz & Sicherheit aktivieren.")
    }

    static func firewall() async -> [SecurityCheckResult] {
        let tool = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        async let globalState = Shell.run(tool, ["--getglobalstate"])
        async let stealthState = Shell.run(tool, ["--getstealthmode"])
        let (global, stealth) = await (globalState, stealthState)

        let fw: SecurityCheckResult
        if let global, global.output.contains("enabled") {
            fw = .init(id: "firewall", title: "Firewall", status: .pass, detail: "Die Programm-Firewall ist aktiv.")
        } else if let global {
            fw = .init(id: "firewall", title: "Firewall", status: .warning, detail: global.output,
                       recommendation: "Firewall unter Systemeinstellungen › Netzwerk › Firewall einschalten.")
        } else {
            fw = .init(id: "firewall", title: "Firewall", status: .error, detail: "socketfilterfw konnte nicht ausgeführt werden.")
        }

        let st: SecurityCheckResult
        if let stealth, stealth.output.localizedCaseInsensitiveContains("stealth mode enabled")
            || stealth.output.contains("is on") {
            st = .init(id: "stealth", title: "Tarnmodus (Stealth Mode)", status: .pass, detail: "Der Mac antwortet nicht auf Ping/Port-Scans.")
        } else {
            st = .init(id: "stealth", title: "Tarnmodus (Stealth Mode)", status: .info,
                       detail: stealth?.output ?? "Status unbekannt.",
                       recommendation: "Optional: Tarnmodus in den Firewall-Optionen aktivieren.")
        }
        return [fw, st]
    }

    /// Services listening on non-loopback addresses (Remote Login, Screen Sharing, File Sharing …).
    static func listeningServices() async -> SecurityCheckResult {
        let title = "Offene Netzwerkdienste"
        guard let r = await Shell.run("/usr/sbin/netstat", ["-an", "-p", "tcp"]) else {
            return .init(id: "ports", title: title, status: .error, detail: "netstat konnte nicht ausgeführt werden.")
        }
        let exposed = parseListeningPorts(r.output)
        let risky: [Int: String] = [
            22: "SSH / Entfernte Anmeldung", 5900: "Bildschirmfreigabe (VNC)", 3283: "Apple Remote Desktop",
            445: "Dateifreigabe (SMB)", 548: "Dateifreigabe (AFP)", 21: "FTP", 23: "Telnet",
        ]
        let riskyOpen = exposed.filter { risky[$0] != nil }.sorted()
        let all = exposed.sorted().map(String.init).joined(separator: ", ")
        if riskyOpen.isEmpty {
            return .init(id: "ports", title: title, status: exposed.isEmpty ? .pass : .info,
                         detail: exposed.isEmpty ? "Keine Dienste lauschen im Netzwerk."
                                                 : "Im Netzwerk erreichbare Ports: \(all)")
        }
        let names = riskyOpen.map { "\($0) (\(risky[$0]!))" }.joined(separator: ", ")
        return .init(id: "ports", title: title, status: .warning,
                     detail: "Fernzugriffsdienste erreichbar: \(names). Alle Ports: \(all)",
                     recommendation: "Nicht benötigte Freigaben unter Systemeinstellungen › Allgemein › Teilen deaktivieren.")
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
        let title = "Ausstehende Apple-Updates"
        guard let r = await Shell.run("/usr/sbin/softwareupdate", ["--list"], timeout: 120), !r.timedOut else {
            return .init(id: "pending-updates", title: title, status: .error,
                         detail: "softwareupdate hat nicht rechtzeitig geantwortet (offline?).")
        }
        let updates = parsePendingUpdates(r.output)
        if updates.isEmpty {
            if r.output.contains("No new software available") {
                return .init(id: "pending-updates", title: title, status: .pass, detail: "Keine ausstehenden Updates.")
            }
            return .init(id: "pending-updates", title: title, status: .info, detail: r.output)
        }
        let critical = updates.contains { u in
            let t = u.lowercased()
            return t.contains("macos") || t.contains("security") || t.contains("sicherheit") || t.contains("safari")
        }
        return .init(id: "pending-updates", title: title, status: critical ? .fail : .warning,
                     detail: updates.joined(separator: "; "),
                     recommendation: "Updates unter Systemeinstellungen › Allgemein › Softwareupdate installieren.")
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
        let title = "Automatische Updates"
        let prefs = NSDictionary(contentsOfFile: "/Library/Preferences/com.apple.SoftwareUpdate.plist") as? [String: Any] ?? [:]
        let keys: [(String, String)] = [
            ("AutomaticCheckEnabled", "Nach Updates suchen"),
            ("AutomaticDownload", "Updates laden"),
            ("CriticalUpdateInstall", "Sicherheitsmaßnahmen und Systemdateien installieren"),
            ("ConfigDataInstall", "XProtect-/Konfigurationsdaten installieren"),
            ("AutomaticallyInstallMacOSUpdates", "macOS-Updates installieren"),
        ]
        var off: [String] = []
        for (key, label) in keys {
            if let value = prefs[key] as? Bool, value == false { off.append(label) }
            if let value = prefs[key] as? Int, value == 0 { off.append(label) }
        }
        let securityOff = off.contains { $0.contains("Sicherheit") || $0.contains("XProtect") }
        if off.isEmpty {
            return .init(id: "updates", title: title, status: .pass,
                         detail: "Keine automatische Update-Option ist explizit deaktiviert.")
        }
        return .init(id: "updates", title: title, status: securityOff ? .fail : .warning,
                     detail: "Deaktiviert: " + off.joined(separator: ", "),
                     recommendation: "Unter Systemeinstellungen › Allgemein › Softwareupdate › Automatische Updates alle Optionen einschalten.")
    }

    static func xprotect() -> SecurityCheckResult {
        let title = "XProtect-Malware-Signaturen"
        let path = "/Library/Apple/System/Library/CoreServices/XProtect.bundle"
        let plist = NSDictionary(contentsOfFile: path + "/Contents/Info.plist") as? [String: Any]
        guard let version = plist?["CFBundleShortVersionString"] as? String else {
            return .init(id: "xprotect", title: title, status: .info, detail: "XProtect-Version nicht lesbar.")
        }
        let modified = (try? FileManager.default.attributesOfItem(atPath: path + "/Contents/Info.plist"))?[.modificationDate] as? Date
        guard let modified else {
            return .init(id: "xprotect", title: title, status: .info, detail: "Version \(version)")
        }
        let days = Int(Date().timeIntervalSince(modified) / 86_400)
        let date = modified.formatted(date: .abbreviated, time: .omitted)
        if days > 90 {
            return .init(id: "xprotect", title: title, status: .warning,
                         detail: "Version \(version), zuletzt aktualisiert am \(date) (vor \(days) Tagen).",
                         recommendation: "Automatische Installation von Sicherheitsdaten aktivieren und nach Updates suchen.")
        }
        return .init(id: "xprotect", title: title, status: .pass,
                     detail: "Version \(version), aktualisiert am \(date).")
    }

    static func automaticLogin() -> SecurityCheckResult {
        let title = "Automatische Anmeldung"
        let prefs = NSDictionary(contentsOfFile: "/Library/Preferences/com.apple.loginwindow.plist") as? [String: Any]
        if let user = prefs?["autoLoginUser"] as? String, !user.isEmpty {
            return .init(id: "autologin", title: title, status: .fail,
                         detail: "Benutzer wird ohne Passwort angemeldet.",
                         recommendation: "Unter Systemeinstellungen › Benutzer:innen & Gruppen die automatische Anmeldung ausschalten.")
        }
        return .init(id: "autologin", title: title, status: .pass, detail: "Automatische Anmeldung ist aus.")
    }

    static func guestAccount() -> SecurityCheckResult {
        let title = "Gastbenutzer"
        let prefs = NSDictionary(contentsOfFile: "/Library/Preferences/com.apple.loginwindow.plist") as? [String: Any]
        if (prefs?["GuestEnabled"] as? Bool) == true {
            return .init(id: "guest", title: title, status: .warning, detail: "Der Gastbenutzer ist aktiviert.",
                         recommendation: "Gastbenutzer unter Systemeinstellungen › Benutzer:innen & Gruppen deaktivieren.")
        }
        return .init(id: "guest", title: title, status: .pass, detail: "Gastbenutzer ist deaktiviert.")
    }
}
