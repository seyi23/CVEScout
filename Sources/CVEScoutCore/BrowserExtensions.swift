import Foundation

/// An installed browser extension with the permissions that matter for security.
public struct BrowserExtension: Codable, Sendable, Hashable, Identifiable {
    public var id: String { "\(browser)|\(profile)|\(extensionID)" }
    public let browser: String
    public let profile: String
    public let extensionID: String
    public let name: String
    public let version: String
    /// Can read and change data on all websites.
    public let broadAccess: Bool
    /// Especially powerful permissions (debugger, nativeMessaging, proxy, cookies …).
    public let sensitivePermissions: [String]
    public let enabled: Bool?

    /// Broad access combined with powerful permissions – worth a second look.
    public var needsReview: Bool { broadAccess && !sensitivePermissions.isEmpty }
}

public enum BrowserExtensionScanner {
    static let chromiumBrowsers: [(name: String, path: String)] = [
        ("Google Chrome", "Google/Chrome"),
        ("Brave", "BraveSoftware/Brave-Browser"),
        ("Microsoft Edge", "Microsoft Edge"),
        ("Vivaldi", "Vivaldi"),
        ("Chromium", "Chromium"),
        ("Arc", "Arc/User Data"),
        ("Opera", "com.operasoftware.Opera"),
    ]

    static let broadPatterns: Set<String> = ["<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "file:///*"]
    static let sensitive: Set<String> = [
        "debugger", "nativeMessaging", "proxy", "management", "cookies", "webRequest", "webRequestBlocking",
        "history", "clipboardRead", "privacy", "browsingData", "downloads", "scripting", "tabCapture", "desktopCapture",
    ]

    public static func scan() -> [BrowserExtension] {
        let support = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support")
        var result: [BrowserExtension] = []
        for browser in chromiumBrowsers {
            result += chromium(browser: browser.name, root: support.appendingPathComponent(browser.path))
        }
        result += firefox(root: support.appendingPathComponent("Firefox/Profiles"))
        result += safari()
        return result.sorted {
            if $0.needsReview != $1.needsReview { return $0.needsReview }
            return ($0.browser, $0.name.lowercased()) < ($1.browser, $1.name.lowercased())
        }
    }

    // MARK: Chromium family

    static func chromium(browser: String, root: URL) -> [BrowserExtension] {
        let fm = FileManager.default
        guard let profiles = try? fm.contentsOfDirectory(atPath: root.path) else { return [] }
        var result: [BrowserExtension] = []
        for profile in profiles where profile == "Default" || profile.hasPrefix("Profile ") {
            let profileURL = root.appendingPathComponent(profile)
            let states = chromiumStates(profileURL)
            let extRoot = profileURL.appendingPathComponent("Extensions")
            for extID in (try? fm.contentsOfDirectory(atPath: extRoot.path)) ?? [] where extID.count == 32 {
                let versions = ((try? fm.contentsOfDirectory(atPath: extRoot.appendingPathComponent(extID).path)) ?? [])
                    .filter { !$0.hasPrefix(".") }
                    .sorted { (Version($0) ?? Version(components: [0])) < (Version($1) ?? Version(components: [0])) }
                guard let latest = versions.last else { continue }
                let dir = extRoot.appendingPathComponent(extID).appendingPathComponent(latest)
                guard let data = try? Data(contentsOf: dir.appendingPathComponent("manifest.json")),
                      let manifest = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
                // Hidden built-in helpers (e.g. Chrome's payment component) have no UI name.
                let name = localizedName(manifest["name"] as? String ?? extID, manifest: manifest, dir: dir)
                var permissions = (manifest["permissions"] as? [Any] ?? []).compactMap { $0 as? String }
                permissions += (manifest["host_permissions"] as? [Any] ?? []).compactMap { $0 as? String }
                for script in manifest["content_scripts"] as? [[String: Any]] ?? [] {
                    permissions += script["matches"] as? [String] ?? []
                }
                result.append(make(browser: browser, profile: profile, id: extID, name: name,
                                   version: manifest["version"] as? String ?? latest, permissions: permissions,
                                   enabled: states[extID]))
            }
        }
        return result
    }

    /// Enabled state from the profile's Preferences (state 1 = enabled). Missing entries → unknown.
    static func chromiumStates(_ profile: URL) -> [String: Bool] {
        var states: [String: Bool] = [:]
        for file in ["Preferences", "Secure Preferences"] {
            guard let data = try? Data(contentsOf: profile.appendingPathComponent(file)),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let settings = (json["extensions"] as? [String: Any])?["settings"] as? [String: Any] else { continue }
            for (id, value) in settings {
                guard let entry = value as? [String: Any] else { continue }
                if let state = entry["state"] as? Int { states[id] = state == 1 }
                if let reasons = entry["disable_reasons"] as? [Any], !reasons.isEmpty { states[id] = false }
                if let reasons = entry["disable_reasons"] as? Int, reasons != 0 { states[id] = false }
            }
        }
        return states
    }

    /// Resolves "__MSG_appName__" from _locales/<default_locale>/messages.json.
    static func localizedName(_ raw: String, manifest: [String: Any], dir: URL) -> String {
        guard raw.hasPrefix("__MSG_"), raw.hasSuffix("__") else { return raw }
        let key = String(raw.dropFirst(6).dropLast(2)).lowercased()
        var locales = [Language.current.rawValue, "en", "en_US"]
        if let def = manifest["default_locale"] as? String { locales.append(def) }
        for locale in locales {
            let url = dir.appendingPathComponent("_locales/\(locale)/messages.json")
            guard let data = try? Data(contentsOf: url),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }
            for (k, v) in json where k.lowercased() == key {
                if let message = (v as? [String: Any])?["message"] as? String { return message }
            }
        }
        return raw
    }

    // MARK: Firefox

    static func firefox(root: URL) -> [BrowserExtension] {
        let fm = FileManager.default
        var result: [BrowserExtension] = []
        for profile in (try? fm.contentsOfDirectory(atPath: root.path)) ?? [] {
            let file = root.appendingPathComponent(profile).appendingPathComponent("extensions.json")
            guard let data = try? Data(contentsOf: file),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let addons = json["addons"] as? [[String: Any]] else { continue }
            let profileName = profile.split(separator: ".", maxSplits: 1).last.map(String.init) ?? profile
            for addon in addons where addon["type"] as? String == "extension" {
                let location = addon["location"] as? String ?? ""
                guard !location.hasPrefix("app-") else { continue }   // built-in / system add-ons
                let locale = addon["defaultLocale"] as? [String: Any]
                let perms = addon["userPermissions"] as? [String: Any] ?? [:]
                let permissions = (perms["permissions"] as? [String] ?? []) + (perms["origins"] as? [String] ?? [])
                result.append(make(browser: "Firefox", profile: profileName, id: addon["id"] as? String ?? "?",
                                   name: locale?["name"] as? String ?? addon["id"] as? String ?? "?",
                                   version: addon["version"] as? String ?? "", permissions: permissions,
                                   enabled: addon["active"] as? Bool))
            }
        }
        return result
    }

    // MARK: Safari

    /// Safari web extensions are app extensions registered with pluginkit.
    static func safari() -> [BrowserExtension] {
        guard let output = try? runPluginkit() else { return [] }
        return parsePluginkit(output)
    }

    static func runPluginkit() throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pluginkit")
        process.arguments = ["-m", "-v", "-p", "com.apple.Safari.web-extension"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    /// Lines look like: "+    de.shoop.extension.extension(3.2.16)\t<uuid>\t<date>\t/Applications/Shoop.app/…/Shoop Extension.appex"
    public static func parsePluginkit(_ output: String) -> [BrowserExtension] {
        output.split(separator: "\n").compactMap { raw in
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { return nil }
            let enabled: Bool? = line.hasPrefix("+") ? true : line.hasPrefix("-") ? false : nil
            let body = line.drop { "+-!= ".contains($0) }
            let fields = body.split(separator: "\t").map { $0.trimmingCharacters(in: .whitespaces) }
            guard let first = fields.first, let open = first.lastIndex(of: "(") else { return nil }
            let id = String(first[..<open])
            let version = String(first[first.index(after: open)...].dropLast())
            // Skip summary lines such as "(2 plug-ins)".
            guard !id.isEmpty, version.first?.isNumber == true, !version.contains(" ") else { return nil }
            let path = fields.last { $0.hasSuffix(".appex") }
            let name = path.map { (($0 as NSString).lastPathComponent as NSString).deletingPathExtension } ?? id
            return BrowserExtension(browser: "Safari", profile: "", extensionID: id, name: name, version: version,
                                    broadAccess: false, sensitivePermissions: [], enabled: enabled)
        }
    }

    // MARK: Helpers

    static func make(browser: String, profile: String, id: String, name: String, version: String,
                     permissions: [String], enabled: Bool?) -> BrowserExtension {
        let broad = permissions.contains { broadPatterns.contains($0) }
        let sensitivePerms = Array(Set(permissions.filter { sensitive.contains($0) })).sorted()
        return BrowserExtension(browser: browser, profile: profile, extensionID: id, name: name, version: version,
                                broadAccess: broad, sensitivePermissions: sensitivePerms, enabled: enabled)
    }

    public static func check(_ extensions: [BrowserExtension]) -> SecurityCheckResult {
        let title = tr("Browser-Erweiterungen", "Browser extensions")
        guard !extensions.isEmpty else {
            return .init(id: "extensions", title: title, status: .pass, detail: tr("Keine Erweiterungen gefunden.", "No extensions found."))
        }
        let broad = extensions.filter(\.broadAccess)
        let review = extensions.filter(\.needsReview)
        let browsers = Set(extensions.map(\.browser)).sorted().joined(separator: ", ")
        var detail = tr("\(extensions.count) Erweiterungen (\(browsers)), \(broad.count) mit Zugriff auf alle Webseiten.",
                        "\(extensions.count) extensions (\(browsers)), \(broad.count) with access to all websites.")
        if !review.isEmpty {
            let names = review.prefix(5).map(\.name).joined(separator: ", ") + (review.count > 5 ? " …" : "")
            detail += " " + tr("Weitreichende Rechte: \(names)", "Powerful permissions: \(names)")
        }
        return .init(id: "extensions", title: title, status: review.isEmpty ? .info : .warning, detail: detail,
                     recommendation: tr("Nicht mehr benötigte Erweiterungen entfernen; nur Erweiterungen bekannter Anbieter behalten.",
                                        "Remove extensions you no longer need; keep only extensions from known publishers."))
    }
}
