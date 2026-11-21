import Foundation

/// Maps local software to BSI CSAF vendor/product names.
///
/// The curated tables use the exact spellings found in the BSI WID feed. Add new
/// entries here (pull requests welcome) – they are the main lever for coverage.
public enum ProductCatalog {
    /// Bundle identifier (exact or prefix ending in ".") → BSI products.
    static let applications: [String: [ProductRef]] = [
        // Apple
        "com.apple.Safari": [.init("Apple", "Safari")],
        "com.apple.dt.Xcode": [.init("Apple", "Xcode")],
        // Browsers
        "com.google.Chrome": [.init("Google", "Chrome")],
        "com.microsoft.edgemac": [.init("Microsoft", "Edge")],
        "org.mozilla.firefox": [.init("Mozilla", "Firefox")],
        "org.mozilla.thunderbird": [.init("Mozilla", "Thunderbird")],
        // Microsoft
        "com.microsoft.VSCode": [.init("Microsoft", "Visual Studio Code")],
        "com.microsoft.teams2": [.init("Microsoft", "Teams")],
        "com.microsoft.teams": [.init("Microsoft", "Teams")],
        // Communication
        "us.zoom.xos": [.init("Zoom Video Communications", "Zoom Client"),
                        .init("Zoom Video Communications", "Zoom Video Communications Workplace")],
        "Cisco-Systems.Spark": [.init("Cisco", "WebEx")],
        "com.cisco.webexmeetingsapp": [.init("Cisco", "WebEx")],
        "net.whatsapp.WhatsApp": [.init("Meta", "WhatsApp")],
        // Remote access / VPN
        "com.teamviewer.TeamViewer": [.init("TeamViewer", "TeamViewer")],
        "com.philandro.anydesk": [.init("AnyDesk", "AnyDesk")],
        "com.fortinet.FortiClient": [.init("Fortinet", "FortiClient")],
        "com.paloaltonetworks.GlobalProtect.client": [.init("Palo Alto Networks", "GlobalProtect")],
        "com.cisco.anyconnect.gui": [.init("Cisco", "AnyConnect Secure Mobility Solution")],
        // Developer tools
        "com.docker.docker": [.init("Docker", "Desktop"), .init("Docker", "Docker Desktop")],
        "com.jetbrains.intellij": [.init("JetBrains", "IntelliJ IDEA")],
        "com.jetbrains.intellij.ce": [.init("JetBrains", "IntelliJ IDEA")],
        "com.jetbrains.pycharm": [.init("JetBrains", "PyCharm")],
        "com.jetbrains.pycharm.ce": [.init("JetBrains", "PyCharm")],
        "com.jetbrains.WebStorm": [.init("JetBrains", "WebStorm")],
        "com.jetbrains.CLion": [.init("JetBrains", "CLion")],
        "com.jetbrains.PhpStorm": [.init("JetBrains", "PhpStorm")],
        "com.jetbrains.datagrip": [.init("JetBrains", "DataGrip")],
        "com.jetbrains.toolbox": [.init("JetBrains", "Toolbox App")],
        "org.wireshark.Wireshark": [.init("Open Source", "Wireshark")],
        "org.filezilla-project.filezilla": [.init("Open Source", "FileZilla")],
        "com.electron.ollama": [.init("Ollama", "Ollama")],
        "com.ollama.ollama": [.init("Ollama", "Ollama")],
        // Virtualisation
        "com.vmware.fusion": [.init("VMware", "Fusion")],
        "org.virtualbox.app.VirtualBox": [.init("Oracle", "VirtualBox")],
        // Office / media / productivity
        "org.libreoffice.script": [.init("Open Source", "LibreOffice")],
        "org.videolan.vlc": [.init("Open Source", "VLC")],
        "org.gimp.gimp-2.10": [.init("Open Source", "GIMP")],
        "org.gimp.gimp": [.init("Open Source", "GIMP")],
        "com.adobe.Reader": [.init("Adobe", "Acrobat Reader"), .init("Adobe", "Acrobat Reader DC")],
        "com.adobe.Acrobat.Pro": [.init("Adobe", "Acrobat"), .init("Adobe", "Acrobat DC")],
        "com.adobe.Photoshop": [.init("Adobe", "Photoshop")],
        "md.obsidian": [.init("Obsidian", "Obsidian")],
        // Password managers
        "org.keepassxc.keepassxc": [.init("Open Source", "KeePassXC")],
        "com.bitwarden.desktop": [.init("Open Source", "Bitwarden")],
    ]

    /// Homebrew formula (without "@major" suffix) → BSI products.
    static let homebrew: [String: [ProductRef]] = [
        "openssl": [.init("Open Source", "OpenSSL")],
        "curl": [.init("Open Source", "cURL")],
        "git": [.init("Open Source", "git")],
        "python": [.init("Open Source", "Python")],
        "node": [.init("Open Source", "Node.js")],
        "openssh": [.init("Open Source", "OpenSSH")],
        "vim": [.init("Open Source", "vim")],
        "ffmpeg": [.init("Open Source", "ffmpeg")],
        "imagemagick": [.init("Open Source", "ImageMagick")],
        "wget": [.init("Open Source", "wget")],
        "sqlite": [.init("Open Source", "SQLite")],
        "gnupg": [.init("Open Source", "GnuPG")],
        "php": [.init("Open Source", "PHP")],
        "ruby": [.init("Open Source", "Ruby")],
        "postgresql": [.init("Open Source", "PostgreSQL")],
        "redis": [.init("Open Source", "Redis")],
        "samba": [.init("Open Source", "Samba")],
        "nginx": [.init("NGINX", "NGINX")],
        "mysql": [.init("Oracle", "MySQL")],
        "mariadb": [.init("MariaDB", "MariaDB")],
        "openjdk": [.init("Open Source", "OpenJDK")],
        "terraform": [.init("Hashicorp", "Terraform")],
        "docker": [.init("Open Source", "docker")],
        "grafana": [.init("Grafana", "Grafana")],
        "ollama": [.init("Ollama", "Ollama")],
        "sudo": [.init("Open Source", "sudo")],
    ]

    public static let macOS = [ProductRef("Apple", "macOS")]

    /// BSI advisories filed under the wrong vendor/product. They are skipped entirely.
    public static var misattributedAdvisories: [String: String] { [
        "WID-SEC-W-2025-2158": tr("CVE-2025-56449 betrifft „Obsidian Scheduler“ (Java-Jobplaner), nicht die Notiz-App Obsidian.", "CVE-2025-56449 concerns “Obsidian Scheduler” (a Java job scheduler), not the Obsidian notes app."),
    ] }

    /// Bundle identifier (exact) → NVD CPE product. Used for apps the BSI does not cover.
    /// Every entry was checked against the NVD CPE dictionary.
    static let cpeApplications: [String: CPEProduct] = [
        "com.hnc.Discord": .init("discord", "discord"),
        "ru.keepcoder.Telegram": .init("telegram", "telegram"),
        "com.tdesktop.Telegram": .init("telegram", "telegram_desktop"),
        "org.whispersystems.signal-desktop": .init("signal", "signal-desktop"),
        "com.1password.1password": .init("1password", "1password"),
        "com.brave.Browser": .init("brave", "brave"),
        "com.spotify.client": .init("spotify", "spotify"),
        "com.googlecode.iterm2": .init("iterm2", "iterm2"),
        "org.filezilla-project.filezilla": .init("filezilla-project", "filezilla_client"),
        "at.obdev.littlesnitch": .init("obdev", "little_snitch"),
        "Electrum": .init("electrum", "electrum"),
        "org.electrum.electrum": .init("electrum", "electrum"),
        "com.ledger.live": .init("ledger", "ledger_live"),
        "notion.id": .init("notion", "notion"),
        "com.postmanlabs.mac": .init("postman", "postman"),
        "ch.sudo.cyberduck": .init("cyberduck", "cyberduck"),
        "org.m0k.transmission": .init("transmissionbt", "transmission"),
        "io.balena.etcher": .init("balena", "etcher"),
        "io.resin.etcher": .init("balena", "etcher"),
        "org.audacityteam.audacity": .init("audacityteam", "audacity"),
        "org.blenderfoundation.blender": .init("blender", "blender"),
        "org.inkscape.Inkscape": .init("inkscape", "inkscape"),
        "net.kovidgoyal.calibre": .init("calibre-ebook", "calibre"),
        "org.torproject.torbrowser": .init("torproject", "tor_browser"),
        "net.mullvad.vpn": .init("mullvad", "mullvad_vpn"),
        "ch.protonvpn.mac": .init("proton", "protonvpn"),
        "com.getdropbox.dropbox": .init("dropbox", "dropbox"),
        "com.parallels.desktop.console": .init("parallels", "parallels_desktop"),
        "net.tunnelblick.tunnelblick": .init("tunnelblick", "tunnelblick"),
        "com.macpaw.CleanMyMac-mas": .init("macpaw", "cleanmymac_x"),
        "com.macpaw.CleanMyMac4": .init("macpaw", "cleanmymac_x"),
    ]

    /// NVD CPE product for an app that has no BSI mapping.
    public static func cpeProduct(for item: SoftwareItem) -> CPEProduct? {
        guard item.source == .application else { return nil }
        return cpeApplications[item.identifier]
    }

    /// Version string as NVD writes it for this product.
    public static func nvdVersion(for item: SoftwareItem, product: CPEProduct) -> String? {
        guard let v = Version(item.version) else { return nil }
        // Brave reports "<chromium major>.<brave version>", NVD uses the Brave version only.
        if product.product == "brave", v.components.count == 4, v.components[0] >= 70 {
            return Version(components: Array(v.components.dropFirst())).description
        }
        return v.description
    }

    public struct Mapping: Sendable {
        public let item: SoftwareItem
        public let refs: [ProductRef]
        public let confidence: MatchConfidence
    }

    /// Curated mapping first; for apps without one, a heuristic over the BSI feed:
    /// a BSI product name equal to the app name whose vendor appears in the bundle identifier.
    public static func mapping(for item: SoftwareItem, feed: BSIFeedIndex?) -> Mapping? {
        switch item.source {
        case .system:
            return Mapping(item: item, refs: macOS, confidence: .curated)
        case .homebrew:
            let base = (item.identifier.split(separator: "@").first.map(String.init) ?? item.identifier).lowercased()
            if let refs = homebrew[base] { return Mapping(item: item, refs: refs, confidence: .curated) }
            // Generic: BSI lists most libraries as vendor "Open Source" with the upstream name.
            guard let feed, base.count >= 3,
                  feed.entries(forProductLowercased: base).contains(where: { $0.vendors.contains("open source") })
            else { return nil }
            let spelling = feed.productSpellings[base]?.sorted().first ?? base
            return Mapping(item: item, refs: [ProductRef("Open Source", spelling)], confidence: .heuristic)
        case .application:
            if let refs = curatedApplicationRefs(bundleID: item.identifier, name: item.name, version: item.version) {
                return Mapping(item: item, refs: refs, confidence: .curated)
            }
            guard let feed, !item.identifier.hasPrefix("com.apple.") else { return nil }
            let refs = heuristicRefs(name: item.name, bundleID: item.identifier, feed: feed)
            return refs.isEmpty ? nil : Mapping(item: item, refs: refs, confidence: .heuristic)
        }
    }

    static func curatedApplicationRefs(bundleID: String, name: String, version: String) -> [ProductRef]? {
        if bundleID == "org.mozilla.firefox", name.contains("ESR") || version.lowercased().contains("esr") {
            return [.init("Mozilla", "Firefox ESR")]
        }
        if let refs = applications[bundleID] { return refs }
        // Prefix entries such as JetBrains EAP builds "com.jetbrains.intellij-EAP".
        return applications.first { bundleID.hasPrefix($0.key + "-") || bundleID.hasPrefix($0.key + ".") }?.value
    }

    static func heuristicRefs(name: String, bundleID: String, feed: BSIFeedIndex) -> [ProductRef] {
        let key = name.lowercased()
        guard key.count >= 4 else { return [] }
        let bundle = bundleID.lowercased().filter { $0.isLetter || $0.isNumber || $0 == "." }
        let entries = feed.entries(forProductLowercased: key)
        guard !entries.isEmpty else { return [] }
        var vendors = Set<String>()
        for e in entries {
            for v in e.vendors {
                let compact = v.filter { $0.isLetter || $0.isNumber }
                if compact.count >= 3, bundle.contains(compact) { vendors.insert(v) }
            }
        }
        let spelling = feed.productSpellings[key]?.first ?? name
        return vendors.sorted().map { ProductRef($0, spelling) }
    }
}
