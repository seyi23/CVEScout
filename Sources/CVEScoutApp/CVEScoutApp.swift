import AppKit
import CVEScoutCore
import SwiftUI

@main
struct CVEScoutApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = ScanModel()

    var body: some Scene {
        WindowGroup("CVEScout") {
            ContentView()
                .environment(model)
                .frame(minWidth: 960, minHeight: 600)
        }
        .commands {
            CommandGroup(after: .newItem) {
                Button("Scan starten") { model.startScan() }
                    .keyboardShortcut("r")
                    .disabled(model.isScanning)
                Button("CVE-Liste importieren …") { model.importWatchlistWithPanel() }
                    .keyboardShortcut("i")
                Divider()
                Button("Bericht als Markdown exportieren …") { model.export(markdown: true) }
                    .keyboardShortcut("e")
                    .disabled(model.report == nil)
                Button("Bericht als JSON exportieren …") { model.export(markdown: false) }
                    .disabled(model.report == nil)
            }
        }

        Settings {
            SettingsView()
                .environment(model)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Needed when started as a bare SwiftPM executable (swift run) instead of an .app bundle.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
