import CVEScoutCore
import SwiftUI
import UniformTypeIdentifiers

enum SidebarItem: String, Hashable, CaseIterable, Identifiable {
    case overview, findings, cveList, software, checks, startup
    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: tr("Übersicht", "Overview")
        case .findings: tr("Schwachstellen", "Vulnerabilities")
        case .cveList: tr("CVE-Liste", "CVE list")
        case .software: "Software"
        case .checks: tr("Systemprüfungen", "System checks")
        case .startup: tr("Autostart & Add-ons", "Startup & Add-ons")
        }
    }

    var icon: String {
        switch self {
        case .overview: "gauge.with.dots.needle.33percent"
        case .findings: "exclamationmark.shield"
        case .cveList: "list.bullet.rectangle"
        case .software: "shippingbox"
        case .checks: "checklist"
        case .startup: "power.circle"
        }
    }
}

struct ContentView: View {
    @Environment(ScanModel.self) private var model
    @State private var dropTargeted = false

    var body: some View {
        NavigationSplitView {
            List(SidebarItem.allCases, selection: Bindable(model).sidebarSelection) { item in
                Label(item.title, systemImage: item.icon)
                    .badge(badge(for: item))
                    .tag(item)
            }
            .navigationSplitViewColumnWidth(min: 210, ideal: 240)
        } detail: {
            Group {
                switch model.sidebarSelection ?? .overview {
                case .overview: OverviewView(selection: Bindable(model).sidebarSelection)
                case .findings: FindingsView()
                case .cveList: CVEListView()
                case .software: SoftwareView()
                case .checks: ChecksView()
                case .startup: StartupView()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                if model.isScanning, let phase = model.phase {
                    HStack(spacing: 8) {
                        if let f = phase.fraction {
                            ProgressView(value: f).frame(width: 80)
                        } else {
                            ProgressView().controlSize(.small)
                        }
                        Text(phase.label).font(.callout).foregroundStyle(.secondary)
                    }
                }
                Button {
                    model.importWatchlistWithPanel()
                } label: {
                    Label(tr("CVE-Liste importieren", "Import CVE list"), systemImage: "square.and.arrow.down")
                }
                .help(tr("Textdatei mit einer CVE pro Zeile importieren und prüfen", "Import and check a text file with one CVE per line"))
                Button {
                    model.startScan()
                } label: {
                    Label(tr("Scan starten", "Start scan"), systemImage: "arrow.clockwise")
                }
                .disabled(model.isScanning)
                .help(tr("Software und Systemeinstellungen prüfen (⌘R)", "Check software and system settings (⌘R)"))
            }
        }
        .onDrop(of: [.fileURL], isTargeted: $dropTargeted) { providers in
            guard let provider = providers.first else { return false }
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                guard let url else { return }
                Task { @MainActor in
                    model.importWatchlist(from: url)
                    model.sidebarSelection = .cveList
                }
            }
            return true
        }
        .alert(tr("Hinweis", "Notice"), isPresented: Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.errorMessage = nil } }
        )) {
            Button("OK") { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "")
        }
    }

    private func badge(for item: SidebarItem) -> Int {
        guard let report = model.report else { return 0 }
        switch item {
        case .findings: return report.confirmedFindings.count
        case .cveList: return report.cveResults?.filter { $0.status == .affected }.count ?? 0
        case .checks: return report.checks.filter { $0.status == .fail || $0.status == .warning }.count
        case .startup: return (report.persistence?.filter { $0.assessment == .warning }.count ?? 0)
            + (report.browserExtensions?.filter(\.needsReview).count ?? 0)
        default: return 0
        }
    }
}

// MARK: - Shared components

struct SeverityBadge: View {
    let severity: Severity

    var body: some View {
        Text(severity.label.uppercased())
            .font(.caption2.weight(.bold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(severity.color.opacity(0.18), in: Capsule())
            .foregroundStyle(severity.color)
    }
}

struct SourceBadge: View {
    let source: AdvisorySource

    var body: some View {
        Text(source.label)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .overlay(Capsule().strokeBorder(.secondary.opacity(0.6)))
            .foregroundStyle(.secondary)
            .help(source == .bsi ? tr("Quelle: BSI WID/CERT-Bund", "Source: BSI WID/CERT-Bund") : tr("Quelle: NIST National Vulnerability Database", "Source: NIST National Vulnerability Database"))
    }
}

struct UncertainBadge: View {
    var body: some View {
        Label(tr("unsicher", "uncertain"), systemImage: "questionmark.diamond")
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Color.gray.opacity(0.2), in: Capsule())
            .foregroundStyle(.secondary)
            .help(tr("Formal zutreffend, aber unplausibel – bitte manuell prüfen", "Formally matching but implausible – please check manually"))
    }
}

struct KEVBadge: View {
    var body: some View {
        Label(tr("aktiv ausgenutzt", "actively exploited"), systemImage: "flame.fill")
            .font(.caption2.weight(.bold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Color.red.opacity(0.18), in: Capsule())
            .foregroundStyle(.red)
            .help(tr("In CISA Known Exploited Vulnerabilities gelistet", "Listed in CISA Known Exploited Vulnerabilities"))
    }
}

extension Severity {
    var color: Color {
        switch self {
        case .critical: .red
        case .high: .orange
        case .medium: .yellow
        case .low: .blue
        case .unknown: .gray
        }
    }
}

extension CheckStatus {
    var icon: String {
        switch self {
        case .pass: "checkmark.circle.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .fail: "xmark.octagon.fill"
        case .info: "info.circle.fill"
        case .error: "questionmark.circle.fill"
        }
    }

    var color: Color {
        switch self {
        case .pass: .green
        case .warning: .orange
        case .fail: .red
        case .info: .blue
        case .error: .gray
        }
    }
}

extension CVEStatus {
    var icon: String {
        switch self {
        case .affected: "xmark.octagon.fill"
        case .patched: "checkmark.circle.fill"
        case .notInstalled: "minus.circle"
        case .unknown: "questionmark.circle"
        }
    }

    var color: Color {
        switch self {
        case .affected: .red
        case .patched: .green
        case .notInstalled: .secondary
        case .unknown: .orange
        }
    }
}

struct EmptyReportView: View {
    @Environment(ScanModel.self) private var model

    var body: some View {
        ContentUnavailableView {
            Label(tr("Noch kein Scan", "No scan yet"), systemImage: "shield.lefthalf.filled")
        } description: {
            Text(tr("CVEScout gleicht installierte Software mit den Sicherheitshinweisen des BSI und der NVD ab und prüft die Sicherheitseinstellungen dieses Macs. Es wird nichts verändert und keine Daten über dein System werden gesendet.", "CVEScout matches the installed software against security advisories from the BSI and the NVD and checks the security settings of this Mac. Nothing is changed and no data about your system is sent."))
        } actions: {
            Button(tr("Scan starten", "Start scan")) { model.startScan() }
                .buttonStyle(.borderedProminent)
                .disabled(model.isScanning)
        }
    }
}
