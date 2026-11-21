import AppKit
import CVEScoutCore
import SwiftUI

/// Launch agents/daemons and browser extensions – things that run automatically.
struct StartupView: View {
    @Environment(ScanModel.self) private var model
    @State private var tab = 0
    @State private var onlyNotable = false

    var body: some View {
        if let report = model.report, let items = report.persistence {
            let extensions = report.browserExtensions ?? []
            VStack(spacing: 0) {
                HStack {
                    Picker("", selection: $tab) {
                        Text(tr("Autostart (\(items.count))", "Launch items (\(items.count))")).tag(0)
                        Text(tr("Browser-Erweiterungen (\(extensions.count))", "Browser extensions (\(extensions.count))")).tag(1)
                    }
                    .pickerStyle(.segmented)
                    .fixedSize()
                    Spacer()
                    Toggle(tr("Nur auffällige", "Notable only"), isOn: $onlyNotable)
                }
                .padding(12)
                Divider()
                if tab == 0 {
                    LaunchItemsTable(items: onlyNotable ? items.filter { $0.assessment != .ok } : items)
                } else {
                    ExtensionsTable(extensions: onlyNotable ? extensions.filter { $0.broadAccess } : extensions)
                }
            }
        } else if model.report != nil {
            ContentUnavailableView {
                Label(tr("Noch nicht geprüft", "Not checked yet"), systemImage: "power.circle")
            } description: {
                Text(tr("Autostart-Objekte und Browser-Erweiterungen werden ab dem nächsten Scan erfasst.",
                        "Launch items and browser extensions are collected from the next scan on."))
            } actions: {
                Button(tr("Scan starten", "Start scan")) { model.startScan() }.disabled(model.isScanning)
            }
        } else {
            EmptyReportView()
        }
    }
}

private struct LaunchItemsTable: View {
    let items: [PersistenceItem]
    @State private var selection = Set<PersistenceItem.ID>()

    var body: some View {
        Table(items, selection: $selection) {
            TableColumn("") { item in
                Image(systemName: item.assessment.icon).foregroundStyle(item.assessment.color)
                    .help(item.assessment.label)
            }
            .width(22)
            TableColumn("Label") { item in
                Text(item.label).foregroundStyle(item.disabled ? .secondary : .primary)
            }
            .width(min: 160, ideal: 240)
            TableColumn(tr("Art", "Kind")) { Text($0.scope.label) }.width(min: 90, ideal: 110)
            TableColumn(tr("Signatur", "Signature")) { item in
                Text(item.signature.displayName)
                    .foregroundStyle(item.signature.kind.isTrusted ? Color.secondary : Color.orange)
                    .help(item.signature.signer ?? item.signature.kind.label)
            }
            .width(min: 110, ideal: 150)
            TableColumn(tr("Programm", "Program")) { item in
                Text(item.scriptPath ?? item.program).lineLimit(1).truncationMode(.middle)
                    .help(([item.program] + item.arguments).joined(separator: " "))
            }
            TableColumn(tr("Hinweise", "Notes")) { Text($0.notes.joined(separator: "; ")).foregroundStyle(.secondary) }
        }
        .contextMenu(forSelectionType: PersistenceItem.ID.self) { ids in
            if let id = ids.first, let item = items.first(where: { $0.id == id }) {
                Button(tr("Plist im Finder zeigen", "Show plist in Finder")) { reveal(item.plistPath) }
                if FileManager.default.fileExists(atPath: item.scriptPath ?? item.program) {
                    Button(tr("Programm im Finder zeigen", "Show program in Finder")) { reveal(item.scriptPath ?? item.program) }
                }
                Button(tr("Pfad kopieren", "Copy path")) {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(item.plistPath, forType: .string)
                }
            }
        }
    }

    private func reveal(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }
}

private struct ExtensionsTable: View {
    let extensions: [BrowserExtension]

    var body: some View {
        if extensions.isEmpty {
            ContentUnavailableView(tr("Keine Erweiterungen", "No extensions"), systemImage: "puzzlepiece.extension")
        } else {
            Table(extensions) {
                TableColumn("") { ext in
                    Image(systemName: ext.needsReview ? "exclamationmark.triangle.fill" : "puzzlepiece.extension")
                        .foregroundStyle(ext.needsReview ? Color.orange : Color.secondary)
                }
                .width(22)
                TableColumn("Browser") { ext in
                    Text(ext.profile.isEmpty || ext.profile == "Default" ? ext.browser : "\(ext.browser) · \(ext.profile)")
                }
                .width(min: 100, ideal: 140)
                TableColumn("Name") { ext in
                    Text(ext.name).foregroundStyle(ext.enabled == false ? .secondary : .primary)
                        .help(ext.extensionID)
                }
                .width(min: 160, ideal: 220)
                TableColumn("Version") { Text($0.version).monospacedDigit() }.width(min: 60, ideal: 80)
                TableColumn(tr("Alle Webseiten", "All websites")) { ext in
                    Text(ext.broadAccess ? tr("ja", "yes") : "–").foregroundStyle(ext.broadAccess ? .orange : .secondary)
                }
                .width(min: 80, ideal: 100)
                TableColumn(tr("Weitreichende Rechte", "Powerful permissions")) {
                    Text($0.sensitivePermissions.joined(separator: ", ")).foregroundStyle(.secondary)
                }
                TableColumn("Status") { ext in
                    Text(ext.enabled.map { $0 ? tr("aktiv", "enabled") : tr("deaktiviert", "disabled") } ?? "–")
                        .foregroundStyle(.secondary)
                }
                .width(min: 70, ideal: 90)
            }
        }
    }
}

extension PersistenceItem.Assessment {
    var icon: String {
        switch self {
        case .ok: "checkmark.circle"
        case .review: "magnifyingglass.circle"
        case .warning: "exclamationmark.triangle.fill"
        }
    }

    var color: Color {
        switch self {
        case .ok: .green
        case .review: .blue
        case .warning: .orange
        }
    }
}
