import Foundation

/// Collects installed software with versions. Read-only: only Info.plist files and
/// Homebrew's `opt` symlinks are read, nothing is executed.
public struct SoftwareInventory: Sendable {
    public var includeApplications = true
    public var includeHomebrew = true

    public init(includeApplications: Bool = true, includeHomebrew: Bool = true) {
        self.includeApplications = includeApplications
        self.includeHomebrew = includeHomebrew
    }

    public func collect() -> [SoftwareItem] {
        var items = [Self.operatingSystem()]
        if includeApplications { items += Self.applications() }
        if includeHomebrew { items += Self.homebrewFormulae() }
        return items
    }

    // MARK: macOS

    public static func operatingSystem() -> SoftwareItem {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        let version = v.patchVersion > 0
            ? "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
            : "\(v.majorVersion).\(v.minorVersion)"
        return SoftwareItem(name: "macOS", identifier: "macos", version: version, source: .system)
    }

    // MARK: Applications

    static var applicationDirectories: [URL] {
        let fm = FileManager.default
        return [
            URL(fileURLWithPath: "/Applications"),
            fm.homeDirectoryForCurrentUser.appendingPathComponent("Applications"),
        ]
    }

    public static func applications() -> [SoftwareItem] {
        var seen = Set<String>()
        var result: [SoftwareItem] = []
        for dir in applicationDirectories {
            for appURL in findApps(in: dir, depth: 2) {
                guard let item = applicationItem(at: appURL) else { continue }
                // Same bundle id twice (e.g. copies): keep the first one.
                guard seen.insert(item.identifier + item.version).inserted else { continue }
                result.append(item)
            }
        }
        return result.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    private static func findApps(in dir: URL, depth: Int) -> [URL] {
        guard depth > 0,
              let entries = try? FileManager.default.contentsOfDirectory(
                  at: dir, includingPropertiesForKeys: [.isDirectoryKey], options: [.skipsHiddenFiles])
        else { return [] }
        var apps: [URL] = []
        for url in entries {
            if url.pathExtension == "app" {
                apps.append(url)
            } else if (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true {
                apps += findApps(in: url, depth: depth - 1)
            }
        }
        return apps
    }

    static func applicationItem(at url: URL) -> SoftwareItem? {
        let plistURL = url.appendingPathComponent("Contents/Info.plist")
        guard let plist = NSDictionary(contentsOf: plistURL) as? [String: Any],
              let bundleID = plist["CFBundleIdentifier"] as? String
        else { return nil }
        let version = (plist["CFBundleShortVersionString"] as? String)
            ?? (plist["CFBundleVersion"] as? String)
            ?? ""
        guard Version(version) != nil else { return nil }
        var name = (plist["CFBundleDisplayName"] as? String)
            ?? (plist["CFBundleName"] as? String)
            ?? url.deletingPathExtension().lastPathComponent
        // Firefox ESR uses the same bundle id and a plain version; the build repository tells them apart.
        if bundleID == "org.mozilla.firefox",
           let ini = try? String(contentsOf: url.appendingPathComponent("Contents/Resources/application.ini"), encoding: .utf8),
           ini.contains("mozilla-esr") {
            name = "Firefox ESR"
        }
        return SoftwareItem(
            name: name.isEmpty ? url.deletingPathExtension().lastPathComponent : name,
            identifier: bundleID,
            version: version.trimmingCharacters(in: .whitespaces),
            source: .application,
            path: url.path
        )
    }

    // MARK: Homebrew

    static let homebrewPrefixes = ["/opt/homebrew", "/usr/local"]

    /// Reads `<prefix>/opt/<formula>` symlinks, which point at the active `Cellar/<formula>/<version>`.
    public static func homebrewFormulae() -> [SoftwareItem] {
        let fm = FileManager.default
        var result: [SoftwareItem] = []
        for prefix in homebrewPrefixes {
            let optDir = URL(fileURLWithPath: prefix).appendingPathComponent("opt")
            guard fm.fileExists(atPath: prefix + "/Cellar"),
                  let names = try? fm.contentsOfDirectory(atPath: optDir.path)
            else { continue }
            for name in names {
                let link = optDir.appendingPathComponent(name)
                guard let dest = try? fm.destinationOfSymbolicLink(atPath: link.path) else { continue }
                // dest like "../Cellar/openssl@3/3.4.0"; aliases (opt/openssl → openssl@3) are skipped.
                let parts = dest.split(separator: "/")
                guard parts.count >= 2, parts[parts.count - 2] == Substring(name) else { continue }
                let version = String(parts[parts.count - 1])
                guard Version(version) != nil else { continue }
                result.append(SoftwareItem(
                    name: name, identifier: name, version: version,
                    source: .homebrew, path: link.resolvingSymlinksInPath().path
                ))
            }
        }
        return result.sorted { $0.name < $1.name }
    }
}
