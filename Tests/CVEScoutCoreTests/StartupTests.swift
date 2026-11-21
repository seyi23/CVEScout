@testable import CVEScoutCore
import Foundation
import Testing

@Suite("Launch items and browser extensions")
struct StartupTests {
    func tempFile(_ name: String, contents: String, executable: Bool = true) throws -> String {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cvescout-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let url = dir.appendingPathComponent(name)
        try contents.write(to: url, atomically: true, encoding: .utf8)
        if executable { try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path) }
        return url.path
    }

    @Test func appleBinaryIsTrusted() {
        let sig = CodeSignature.inspect(path: "/bin/ls")
        #expect(sig.kind == .apple)
        #expect(sig.kind.isTrusted)
    }

    @Test func missingAndUnsigned() throws {
        #expect(CodeSignature.inspect(path: "/nonexistent/cvescout-test").kind == .missing)
        let path = try tempFile("tool", contents: "not a binary")
        #expect(CodeSignature.inspect(path: path).kind == .unsigned)
    }

    @Test func shortSignerName() {
        #expect(CodeSignature.shortSigner("Developer ID Application: Adobe Inc. (JQ525L2MZD)") == "Adobe Inc.")
    }

    @Test func assessments() throws {
        let script = try tempFile("start.sh", contents: "#!/bin/sh\necho hi\n")
        let viaInterpreter = PersistenceScanner.item(
            plist: ["Label": "com.example.agent", "ProgramArguments": ["/usr/bin/osascript", "/Users/x/run.scpt"]],
            path: "/tmp/a.plist", scope: .userAgent)
        #expect(viaInterpreter.assessment == .review)
        #expect(viaInterpreter.scriptPath == "/Users/x/run.scpt")

        let orphan = PersistenceScanner.item(plist: ["Label": "old", "Program": "/Applications/Gone.app/Contents/MacOS/Gone"],
                                             path: "/tmp/b.plist", scope: .systemDaemon)
        #expect(orphan.assessment == .review)
        #expect(orphan.signature.kind == .missing)

        let unsignedScript = PersistenceScanner.item(plist: ["Label": "s", "Program": script], path: "/tmp/c.plist", scope: .systemDaemon)
        #expect(unsignedScript.assessment == .review)

        let binary = try tempFile("helper", contents: "\u{7F}ELF fake")
        let unsigned = PersistenceScanner.item(plist: ["Label": "u", "Program": binary], path: "/tmp/d.plist", scope: .systemDaemon)
        #expect(unsigned.assessment == .warning)

        let signed = PersistenceScanner.item(plist: ["Label": "ok", "Program": "/bin/ls"], path: "/tmp/e.plist", scope: .userAgent)
        #expect(signed.assessment == .ok)
    }

    @Test func safariPluginkitParsing() {
        let output = """
             de.shoop.extension.extension(3.2.16)\tA1B2\t2026-01-01 10:00:00 +0000\t/Applications/Shoop.app/Contents/PlugIns/Shoop Extension.appex
        +    ca.cgagnier.cookie-editor.Extension(1.13.0)\tC3D4\t2026-01-01 10:00:00 +0000\t/Applications/Cookie-Editor.app/Contents/PlugIns/Cookie-Editor Extension.appex
             (2 plug-ins)
        """
        let exts = BrowserExtensionScanner.parsePluginkit(output)
        #expect(exts.map(\.extensionID) == ["de.shoop.extension.extension", "ca.cgagnier.cookie-editor.Extension"])
        #expect(exts[1].name == "Cookie-Editor Extension")
        #expect(exts[1].enabled == true)
    }

    @Test func extensionPermissions() {
        let e = BrowserExtensionScanner.make(browser: "Chrome", profile: "Default", id: "x", name: "X", version: "1",
                                             permissions: ["<all_urls>", "nativeMessaging", "storage"], enabled: true)
        #expect(e.broadAccess)
        #expect(e.sensitivePermissions == ["nativeMessaging"])
        #expect(e.needsReview)
    }

    @Test func diffReportsNewLaunchItems() {
        func report(_ labels: [String]) -> ScanReport {
            var r = ScanReport(date: Date(), osVersion: "27", inventory: [], findings: [], checks: [], mappedSoftwareIDs: [],
                               advisoriesEvaluated: 0, bsiFeedDate: nil, kevCatalogVersion: nil, warnings: [])
            r.persistence = labels.map {
                PersistenceItem(label: $0, plistPath: "/Library/LaunchAgents/\($0).plist", scope: .systemAgent, program: "/bin/ls",
                                arguments: [], runAtLoad: true, disabled: false,
                                signature: CodeSignature(kind: .apple, signer: nil, teamID: nil), scriptPath: nil,
                                assessment: .ok, notes: [])
            }
            return r
        }
        let diff = ReportDiff(current: report(["a", "b"]), previous: report(["a"]))
        #expect(diff.newLaunchItems.map(\.label) == ["b"])
        #expect(diff.notificationText != nil)
        // No previous data → nothing is "new".
        #expect(ReportDiff(current: report(["a"]), previous: nil).newLaunchItems.isEmpty)
    }
}
