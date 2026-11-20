import CVEScoutCore
import SwiftUI
import UniformTypeIdentifiers

enum SidebarItem: String, Hashable, CaseIterable, Identifiable {
    case overview, findings, cveList, software, checks
    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: "Übersicht"
        case .findings: "Schwachstellen"
        case .cveList: "CVE-Liste"
        case .software: "Software"
        case .checks: "Systemprüfungen"
        }
    }

    var icon: String {
        switch self {
        case .overview: "gauge.with.dots.needle.33percent"
        case .findings: "exclamationmark.shield"
        case .cveList: "list.bullet.rectangle"
        case .software: "shippingbox"
        case .checks: "checklist"
        }
    }
}

struct ContentView: View {
    @Environment(ScanModel.self) private var model
    @State private var selection: SidebarItem? = .overview
    @State private var dropTargeted = false

    var body: some View {
        NavigationSplitView {
            List(SidebarItem.allCases, selection: $selection) { item in
                Label(item.title, systemImage: item.icon)
                    .badge(badge(for: item))
                    .tag(item)
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 210)
        } detail: {
            Group {
                switch selection ?? .overview {
                case .overview: OverviewView(selection: $selection)
                case .findings: FindingsView()
                case .cveList: CVEListView()
                case .software: SoftwareView()
                case .checks: ChecksView()
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
                    Label("CVE-Liste importieren", systemImage: "square.and.arrow.down")
                }
                .help("Textdatei mit einer CVE pro Zeile importieren und prüfen")
                Button {
                    model.startScan()
                } label: {
                    Label("Scan starten", systemImage: "arrow.clockwise")
                }
                .disabled(model.isScanning)
                .help("Software und Systemeinstellungen prüfen (⌘R)")
            }
        }
        .onDrop(of: [.fileURL], isTargeted: $dropTargeted) { providers in
            guard let provider = providers.first else { return false }
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                guard let url else { return }
                Task { @MainActor in
                    model.importWatchlist(from: url)
                    selection = .cveList
                }
            }
            return true
        }
        .alert("Hinweis", isPresented: Binding(
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
            .help(source == .bsi ? "Quelle: BSI WID/CERT-Bund" : "Quelle: NIST National Vulnerability Database")
    }
}

struct UncertainBadge: View {
    var body: some View {
        Label("unsicher", systemImage: "questionmark.diamond")
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Color.gray.opacity(0.2), in: Capsule())
            .foregroundStyle(.secondary)
            .help("Formal zutreffend, aber unplausibel – bitte manuell prüfen")
    }
}

struct KEVBadge: View {
    var body: some View {
        Label("aktiv ausgenutzt", systemImage: "flame.fill")
            .font(.caption2.weight(.bold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Color.red.opacity(0.18), in: Capsule())
            .foregroundStyle(.red)
            .help("In CISA Known Exploited Vulnerabilities gelistet")
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
            Label("Noch kein Scan", systemImage: "shield.lefthalf.filled")
        } description: {
            Text("CVEScout gleicht installierte Software mit den Sicherheitshinweisen des BSI und der NVD ab und prüft die Sicherheitseinstellungen dieses Macs. Es wird nichts verändert und keine Daten über dein System werden gesendet.")
        } actions: {
            Button("Scan starten") { model.startScan() }
                .buttonStyle(.borderedProminent)
                .disabled(model.isScanning)
        }
    }
}
