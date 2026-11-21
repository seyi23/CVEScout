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
                .environment(\.locale, Language.current.locale)
                .frame(minWidth: 960, minHeight: 600)
        }
        .commands {
            CommandGroup(after: .newItem) {
                Button(tr("Scan starten", "Start scan")) { model.startScan() }
                    .keyboardShortcut("r")
                    .disabled(model.isScanning)
                Button(tr("CVE-Liste importieren …", "Import CVE list …")) { model.importWatchlistWithPanel() }
                    .keyboardShortcut("i")
                Divider()
                Button(tr("Bericht als Markdown exportieren …", "Export report as Markdown …")) { model.export(markdown: true) }
                    .keyboardShortcut("e")
                    .disabled(model.report == nil)
                Button(tr("Bericht als JSON exportieren …", "Export report as JSON …")) { model.export(markdown: false) }
                    .disabled(model.report == nil)
            }
        }

        MenuBarExtra {
            MenuBarView()
                .environment(model)
                .environment(\.locale, Language.current.locale)
        } label: {
            Image(systemName: model.statusSymbol)
                .accessibilityLabel("CVEScout: \(model.statusHeadline)")
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .environment(model)
                .environment(\.locale, Language.current.locale)
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
        if DemoData.isEnabled {
            // Fixed, roomy window for reproducible screenshots.
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                for window in NSApp.windows where window.isVisible && window.canBecomeMain {
                    window.setFrame(NSRect(x: 80, y: 80, width: 1240, height: 780), display: true)
                }
            }
        }
    }

    /// The app keeps running in the menu bar when the window is closed.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }
}
