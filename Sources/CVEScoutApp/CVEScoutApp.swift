import AppKit
import CVEScoutCore
import SwiftUI
import UserNotifications

@main
struct CVEScoutApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = ScanModel()

    var body: some Scene {
        Window("CVEScout", id: MainWindow.id) {
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

        MenuBarExtra {
            MenuBarView()
                .environment(model)
        } label: {
            Image(systemName: model.statusSymbol)
                .accessibilityLabel("CVEScout: \(model.statusHeadline)")
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .environment(model)
        }
    }
}

enum MainWindow {
    static let id = "main"
}

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        let showDock = UserDefaults.standard.object(forKey: "showDockIcon") as? Bool ?? true
        ScanModel.applyDockPolicy(showDock)
        if showDock { NSApp.activate(ignoringOtherApps: true) }
        if ScanModel.canNotify { UNUserNotificationCenter.current().delegate = self }
    }

    /// The app keeps running in the menu bar when the window is closed.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }
}
