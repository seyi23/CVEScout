import Foundation
import Security

// MARK: - Code signatures

public enum SignatureKind: String, Codable, Sendable {
    case apple, developerID, appStore, adhoc, unsigned, invalid, missing, unreadable

    public var label: String {
        switch self {
        case .apple: "Apple"
        case .developerID: "Developer ID"
        case .appStore: "App Store"
        case .adhoc: tr("ad-hoc signiert", "ad-hoc signed")
        case .unsigned: tr("nicht signiert", "unsigned")
        case .invalid: tr("Signatur ungültig", "invalid signature")
        case .missing: tr("Datei fehlt", "file missing")
        case .unreadable: tr("nicht prüfbar (nur root)", "not checkable (root only)")
        }
    }

    /// Signed by Apple or an identified developer and the signature is valid.
    public var isTrusted: Bool { self == .apple || self == .developerID || self == .appStore }
}

public struct CodeSignature: Codable, Sendable, Hashable {
    public let kind: SignatureKind
    /// e.g. "Developer ID Application: Adobe Inc. (JQ525L2MZD)" or "Software Signing"
    public let signer: String?
    public let teamID: String?

    public var displayName: String {
        switch kind {
        case .developerID, .appStore: signer.map(Self.shortSigner) ?? kind.label
        default: kind.label
        }
    }

    /// "Developer ID Application: Adobe Inc. (JQ525L2MZD)" → "Adobe Inc."
    static func shortSigner(_ s: String) -> String {
        var name = s
        if let colon = name.firstIndex(of: ":") { name = String(name[name.index(after: colon)...]) }
        if let paren = name.lastIndex(of: "(") { name = String(name[..<paren]) }
        return name.trimmingCharacters(in: .whitespaces)
    }

    /// Reads the static code signature of a file or bundle with the Security framework (no subprocess).
    public static func inspect(path: String) -> CodeSignature {
        guard FileManager.default.fileExists(atPath: path) else { return .init(kind: .missing, signer: nil, teamID: nil) }
        guard FileManager.default.isReadableFile(atPath: path) else { return .init(kind: .unreadable, signer: nil, teamID: nil) }
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let code = staticCode else { return .init(kind: .unsigned, signer: nil, teamID: nil) }

        var infoRef: CFDictionary?
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation)
        guard SecCodeCopySigningInformation(code, flags, &infoRef) == errSecSuccess,
              let info = infoRef as? [String: Any] else { return .init(kind: .unsigned, signer: nil, teamID: nil) }

        // No identifier → not signed at all.
        guard info[kSecCodeInfoIdentifier as String] != nil else { return .init(kind: .unsigned, signer: nil, teamID: nil) }
        let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String
        let certs = info[kSecCodeInfoCertificates as String] as? [SecCertificate] ?? []
        let leaf = certs.first.flatMap { SecCertificateCopySubjectSummary($0) as String? }

        let codeFlags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let isAdhoc = codeFlags & 0x0002 != 0   // kSecCodeSignatureAdhoc
        if isAdhoc || certs.isEmpty { return .init(kind: .adhoc, signer: nil, teamID: teamID) }

        guard SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess else {
            return .init(kind: .invalid, signer: leaf, teamID: teamID)
        }
        let kind: SignatureKind
        switch leaf ?? "" {
        case let s where s.hasPrefix("Developer ID"): kind = .developerID
        case let s where s.hasPrefix("Apple Mac OS Application Signing"): kind = .appStore
        case let s where s == "Software Signing" || s.hasPrefix("Apple "): kind = .apple
        default: kind = teamID == nil ? .apple : .developerID
        }
        return .init(kind: kind, signer: leaf, teamID: teamID)
    }
}

// MARK: - Launch agents / daemons

/// A launchd job that starts automatically (LaunchAgents / LaunchDaemons).
public struct PersistenceItem: Codable, Sendable, Hashable, Identifiable {
    public enum Scope: String, Codable, Sendable {
        case userAgent, systemAgent, systemDaemon

        public var label: String {
            switch self {
            case .userAgent: tr("Benutzer-Agent", "User agent")
            case .systemAgent: tr("System-Agent", "System agent")
            case .systemDaemon: tr("System-Dienst", "System daemon")
            }
        }
    }

    public enum Assessment: String, Codable, Sendable, Comparable {
        case ok, review, warning

        public var label: String {
            switch self {
            case .ok: "OK"
            case .review: tr("prüfen", "review")
            case .warning: tr("Warnung", "warning")
            }
        }

        static let order: [Assessment] = [.ok, .review, .warning]
        public static func < (a: Assessment, b: Assessment) -> Bool { order.firstIndex(of: a)! < order.firstIndex(of: b)! }
    }

    public var id: String { plistPath }
    public let label: String
    public let plistPath: String
    public let scope: Scope
    /// Program that launchd starts (Program or ProgramArguments[0]).
    public let program: String
    public let arguments: [String]
    public let runAtLoad: Bool
    public let disabled: Bool
    public let signature: CodeSignature
    /// For interpreters (sh, osascript, python …): the script that is actually run.
    public let scriptPath: String?
    public let assessment: Assessment
    public let notes: [String]
}

public enum PersistenceScanner {
    static let interpreters: Set<String> = [
        "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "osascript", "python", "python3", "perl", "ruby",
        "node", "php", "tclsh", "swift", "curl", "wget", "nc", "ncat",
    ]

    static var directories: [(String, PersistenceItem.Scope)] {
        [
            (FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/LaunchAgents").path, .userAgent),
            ("/Library/LaunchAgents", .systemAgent),
            ("/Library/LaunchDaemons", .systemDaemon),
        ]
    }

    public static func scan() -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        for (dir, scope) in directories {
            let files = (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
            for file in files where file.hasSuffix(".plist") {
                let path = dir + "/" + file
                guard let plist = NSDictionary(contentsOfFile: path) as? [String: Any] else { continue }
                items.append(item(plist: plist, path: path, scope: scope))
            }
        }
        return items.sorted {
            if $0.assessment != $1.assessment { return $0.assessment > $1.assessment }
            return $0.label.localizedCaseInsensitiveCompare($1.label) == .orderedAscending
        }
    }

    static func item(plist: [String: Any], path: String, scope: PersistenceItem.Scope) -> PersistenceItem {
        let label = plist["Label"] as? String ?? (path as NSString).lastPathComponent
        let args = plist["ProgramArguments"] as? [String] ?? []
        let program = plist["Program"] as? String ?? args.first ?? ""
        let runAtLoad = plist["RunAtLoad"] as? Bool ?? false
        let disabled = plist["Disabled"] as? Bool ?? false
        let signature = CodeSignature.inspect(path: program)

        var notes: [String] = []
        var assessment = PersistenceItem.Assessment.ok
        func raise(_ level: PersistenceItem.Assessment, _ note: String) {
            assessment = max(assessment, level)
            notes.append(note)
        }

        // Script run through an interpreter: the signed binary says nothing about the script.
        var scriptPath: String?
        let programName = (program as NSString).lastPathComponent
        let baseName = programName.replacingOccurrences(of: #"[0-9.]+$"#, with: "", options: .regularExpression)
        if interpreters.contains(programName) || interpreters.contains(baseName) {
            scriptPath = args.dropFirst().first { $0.hasPrefix("/") || $0.hasPrefix("~") }
            raise(.review, tr("startet ein Skript über \(programName)", "runs a script via \(programName)")
                + (scriptPath.map { ": \($0)" } ?? ""))
        }

        switch signature.kind {
        case .missing:
            raise(.review, tr("Programm existiert nicht mehr (verwaister Eintrag)", "program no longer exists (orphaned entry)"))
        case .unsigned where isScript(program):
            raise(.review, tr("Shell-Skript ohne Signatur", "unsigned shell script"))
        case .unsigned, .adhoc, .invalid:
            raise(.warning, tr("Programm ist \(signature.kind.label)", "program is \(signature.kind.label)"))
        default:
            break
        }

        let suspiciousDirs = ["/tmp/", "/private/tmp/", "/var/tmp/", "/Users/Shared/", "/Downloads/"]
        for target in [program, scriptPath].compactMap({ $0 }) where suspiciousDirs.contains(where: { target.contains($0) }) {
            raise(.warning, tr("liegt in einem ungewöhnlichen Ordner: \(target)", "located in an unusual folder: \(target)"))
        }
        if (program as NSString).lastPathComponent.hasPrefix(".") || label.hasPrefix(".") {
            raise(.warning, tr("versteckter Name", "hidden name"))
        }

        return PersistenceItem(
            label: label, plistPath: path, scope: scope, program: program, arguments: Array(args.dropFirst()),
            runAtLoad: runAtLoad, disabled: disabled, signature: signature, scriptPath: scriptPath,
            assessment: assessment, notes: notes
        )
    }

    /// True for text files starting with a shebang ("#!").
    static func isScript(_ path: String) -> Bool {
        guard let handle = FileHandle(forReadingAtPath: path) else { return false }
        defer { try? handle.close() }
        return (try? handle.read(upToCount: 2)) == Data("#!".utf8)
    }

    /// Summary for the system checks list.
    public static func check(_ items: [PersistenceItem]) -> SecurityCheckResult {
        let title = tr("Autostart-Objekte (launchd)", "Launch items (launchd)")
        let warnings = items.filter { $0.assessment == .warning }
        let reviews = items.filter { $0.assessment == .review }
        let names = { (list: [PersistenceItem]) in list.prefix(5).map(\.label).joined(separator: ", ") + (list.count > 5 ? " …" : "") }
        if !warnings.isEmpty {
            return .init(id: "persistence", title: title, status: .warning,
                         detail: tr("\(items.count) Einträge, \(warnings.count) auffällig: \(names(warnings))",
                                    "\(items.count) entries, \(warnings.count) suspicious: \(names(warnings))"),
                         recommendation: tr("Unbekannte Einträge prüfen und ggf. mit dem Deinstallationsprogramm des Herstellers entfernen.",
                                            "Review unknown entries and remove them with the vendor's uninstaller if needed."))
        }
        if !reviews.isEmpty {
            return .init(id: "persistence", title: title, status: .info,
                         detail: tr("\(items.count) Einträge, \(reviews.count) zum Prüfen: \(names(reviews))",
                                    "\(items.count) entries, \(reviews.count) to review: \(names(reviews))"))
        }
        return .init(id: "persistence", title: title, status: .pass,
                     detail: tr("\(items.count) Einträge, alle von Apple oder bekannten Entwicklern signiert.",
                                "\(items.count) entries, all signed by Apple or identified developers."))
    }
}
