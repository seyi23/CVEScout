import AppKit
import CVEScoutCore
import SwiftUI

/// Compact status panel shown from the menu bar icon.
struct MenuBarView: View {
    @Environment(ScanModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            if model.isScanning, let phase = model.phase {
                VStack(alignment: .leading, spacing: 4) {
                    if let f = phase.fraction { ProgressView(value: f) } else { ProgressView().progressViewStyle(.linear) }
                    Text(phase.label).font(.caption).foregroundStyle(.secondary)
                }
            }
            if let report = model.report {
                counts(report)
                topFindings(report)
            }
            Divider()
            actions
            footer
        }
        .padding(14)
        .frame(width: 330)
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: model.statusSymbol)
                .font(.system(size: 28))
                .foregroundStyle(model.statusColor)
            VStack(alignment: .leading, spacing: 2) {
                Text(model.statusHeadline).font(.headline)
                if let date = model.report?.date {
                    Text("Letzter Scan \(date.formatted(.relative(presentation: .named)))")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
        }
    }

    private func counts(_ report: ScanReport) -> some View {
        HStack(spacing: 8) {
            CountChip(value: report.vulnerableSoftwareCount, label: "Programme",
                      tint: report.vulnerableSoftwareCount > 0 ? .orange : .green)
            CountChip(value: report.exploitedCount, label: "ausgenutzt",
                      tint: report.exploitedCount > 0 ? .red : .green)
            let problems = report.checks.filter { $0.status == .fail || $0.status == .warning }.count
            CountChip(value: problems, label: "Einstellungen", tint: problems > 0 ? .orange : .green)
        }
    }

    @ViewBuilder
    private func topFindings(_ report: ScanReport) -> some View {
        // One line per affected program, most severe first.
        let byProgram = report.confirmedFindings.reduce(into: [(SoftwareItem, Finding)]()) { result, f in
            if !result.contains(where: { $0.0.id == f.software.id }) { result.append((f.software, f)) }
        }
        if !byProgram.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(byProgram.prefix(5), id: \.0.id) { item, worst in
                    Button {
                        open(.findings)
                    } label: {
                        HStack(spacing: 6) {
                            Circle().fill(worst.effectiveSeverity.color).frame(width: 7, height: 7)
                            Text("\(item.name) \(item.version)").lineLimit(1)
                            Spacer()
                            if !worst.exploited.isEmpty { Image(systemName: "flame.fill").foregroundStyle(.red) }
                            if let fix = worst.fixedVersions.first {
                                Text("→ \(fix)").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                            }
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
                if byProgram.count > 5 {
                    Text("+ \(byProgram.count - 5) weitere").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        if let diff = model.lastDiff, !diff.resolvedFindings.isEmpty {
            Label("\(diff.resolvedFindings.count) Hinweise seit dem letzten Scan erledigt", systemImage: "checkmark.circle")
                .font(.caption).foregroundStyle(.green)
        }
    }

    private var actions: some View {
        VStack(alignment: .leading, spacing: 2) {
            MenuRow(title: "Jetzt scannen", systemImage: "arrow.clockwise") { model.startScan() }
                .disabled(model.isScanning)
            MenuRow(title: "CVEScout öffnen", systemImage: "macwindow") { open(nil) }
            MenuRow(title: "CVE-Liste importieren …", systemImage: "square.and.arrow.down") {
                NSApp.activate(ignoringOtherApps: true)
                model.importWatchlistWithPanel()
                if model.watchlist != nil { open(.cveList) }
            }
            SettingsLink {
                Label("Einstellungen …", systemImage: "gearshape").frame(maxWidth: .infinity, alignment: .leading)
            }
            .buttonStyle(MenuRowStyle())
            MenuRow(title: "CVEScout beenden", systemImage: "power") { NSApp.terminate(nil) }
        }
    }

    private var footer: some View {
        Group {
            if let next = model.nextAutomaticScan, model.autoScanInterval != .off {
                Text("Automatischer Scan: \(model.autoScanInterval.label.lowercased()) · nächster \(next.formatted(.relative(presentation: .named)))")
            } else {
                Text("Automatischer Scan ist ausgeschaltet")
            }
        }
        .font(.caption2)
        .foregroundStyle(.secondary)
    }

    private func open(_ item: SidebarItem?) {
        if let item { model.sidebarSelection = item }
        openWindow(id: MainWindow.id)
        NSApp.activate(ignoringOtherApps: true)
    }
}

private struct CountChip: View {
    let value: Int
    let label: String
    let tint: Color

    var body: some View {
        VStack(spacing: 2) {
            Text("\(value)").font(.title3.weight(.semibold)).monospacedDigit().foregroundStyle(tint)
            Text(label).font(.caption2).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct MenuRow: View {
    let title: String
    let systemImage: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: systemImage).frame(maxWidth: .infinity, alignment: .leading)
        }
        .buttonStyle(MenuRowStyle())
    }
}

/// Menu-like rows: full width, highlighted on hover.
private struct MenuRowStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        MenuRowBody(configuration: configuration)
    }

    private struct MenuRowBody: View {
        let configuration: Configuration
        @State private var hovering = false
        @Environment(\.isEnabled) private var isEnabled

        var body: some View {
            configuration.label
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .background(hovering && isEnabled ? Color.accentColor.opacity(0.85) : .clear,
                            in: RoundedRectangle(cornerRadius: 5))
                .foregroundStyle(hovering && isEnabled ? Color.white : Color.primary)
                .opacity(isEnabled ? 1 : 0.45)
                .contentShape(Rectangle())
                .onHover { hovering = $0 }
        }
    }
}
