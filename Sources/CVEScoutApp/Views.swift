import CVEScoutCore
import SwiftUI

// MARK: - Overview

struct OverviewView: View {
    @Environment(ScanModel.self) private var model
    @Binding var selection: SidebarItem?

    var body: some View {
        if let report = model.report {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    header(report)
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 180), spacing: 12)], spacing: 12) {
                        StatTile(title: "Betroffene Programme", value: report.vulnerableSoftwareCount,
                                 tint: report.vulnerableSoftwareCount > 0 ? .orange : .green) { selection = .findings }
                        StatTile(title: "Zutreffende Hinweise (BSI/NVD)", value: report.confirmedFindings.count,
                                 tint: report.confirmedFindings.isEmpty ? .green : .orange) { selection = .findings }
                        if !report.uncertainFindings.isEmpty {
                            StatTile(title: "Unsichere Treffer (prüfen)", value: report.uncertainFindings.count,
                                     tint: .secondary) { selection = .findings }
                        }
                        StatTile(title: "Aktiv ausgenutzte CVEs", value: report.exploitedCount,
                                 tint: report.exploitedCount > 0 ? .red : .green) { selection = .findings }
                        let problems = report.checks.filter { $0.status == .fail || $0.status == .warning }.count
                        StatTile(title: "Auffällige Einstellungen", value: problems,
                                 tint: problems > 0 ? .orange : .green) { selection = .checks }
                        if let results = report.cveResults {
                            let hit = results.filter { $0.status == .affected }.count
                            StatTile(title: "CVE-Liste: betroffen", value: hit,
                                     subtitle: "von \(results.count)",
                                     tint: hit > 0 ? .red : .green) { selection = .cveList }
                        }
                    }
                    severityBreakdown(report)
                    sources(report)
                    if !report.warnings.isEmpty {
                        GroupBox("Hinweise") {
                            VStack(alignment: .leading, spacing: 4) {
                                ForEach(report.warnings, id: \.self) { Text("• " + $0) }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    Text("CVEScout vergleicht Versionsnummern mit veröffentlichten Sicherheitshinweisen. Es werden keine Exploits ausgeführt. Ergebnisse ohne Gewähr – Details stehen jeweils im verlinkten BSI-Hinweis.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .padding(24)
            }
        } else {
            EmptyReportView()
        }
    }

    private func header(_ report: ScanReport) -> some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 4) {
                Text("macOS \(report.osVersion)").font(.largeTitle.weight(.semibold))
                Text("Letzter Scan: \(report.date.formatted(date: .abbreviated, time: .shortened))")
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }

    private func severityBreakdown(_ report: ScanReport) -> some View {
        GroupBox("Schweregrade") {
            HStack(spacing: 16) {
                ForEach(Severity.allCases.reversed(), id: \.self) { sev in
                    let n = report.confirmedFindings.filter { $0.effectiveSeverity == sev }.count
                    if n > 0 || sev != .unknown {
                        HStack(spacing: 6) {
                            SeverityBadge(severity: sev)
                            Text("\(n)").monospacedDigit()
                        }
                    }
                }
                Spacer()
            }
            .padding(.vertical, 4)
        }
    }

    private func sources(_ report: ScanReport) -> some View {
        GroupBox("Datenbasis") {
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                GridRow {
                    Text("Erfasste Software").foregroundStyle(.secondary)
                    Text("\(report.inventory.count), davon \(report.mappedSoftwareIDs.count) mit BSI-Zuordnung")
                }
                GridRow {
                    Text("BSI WID/CERT-Bund").foregroundStyle(.secondary)
                    Text("\(report.advisoriesEvaluated) Hinweise ausgewertet\(report.bsiFeedDate.map { ", Stand \($0.formatted(date: .abbreviated, time: .shortened))" } ?? "")")
                }
                GridRow {
                    Text("NIST NVD").foregroundStyle(.secondary)
                    let n = report.confirmedFindings.filter { $0.advisory.origin == .nvd }.count
                    Text(model.useNVD ? "\(n) zutreffende CVEs (für Programme ohne BSI-Abdeckung)" : "deaktiviert")
                }
                GridRow {
                    Text("CISA KEV").foregroundStyle(.secondary)
                    Text(report.kevCatalogVersion.map { "Katalog \($0)" } ?? "nicht verfügbar")
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 4)
        }
    }
}

struct StatTile: View {
    let title: String
    let value: Int
    var subtitle: String? = nil
    let tint: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text("\(value)").font(.system(size: 34, weight: .semibold, design: .rounded)).monospacedDigit()
                        .foregroundStyle(tint)
                    if let subtitle { Text(subtitle).foregroundStyle(.secondary) }
                }
                Text(title).font(.callout).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(14)
            .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
            .contentShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Findings

struct FindingsView: View {
    @Environment(ScanModel.self) private var model
    @State private var selected: Finding.ID?
    @State private var search = ""

    var body: some View {
        if let report = model.report {
            let findings = report.findings.filter { f in
                search.isEmpty
                    || f.software.name.localizedCaseInsensitiveContains(search)
                    || f.advisory.title.localizedCaseInsensitiveContains(search)
                    || f.advisory.cves.contains { $0.localizedCaseInsensitiveContains(search) }
            }
            if report.findings.isEmpty {
                ContentUnavailableView("Keine bekannten Schwachstellen",
                                       systemImage: "checkmark.shield",
                                       description: Text("Für die erfasste Software liegen keine zutreffenden BSI-Hinweise vor."))
            } else {
                HSplitView {
                    List(selection: $selected) {
                        let groups = Dictionary(grouping: findings, by: \.software.id)
                        let order = findings.map(\.software.id).reduce(into: [String]()) { if !$0.contains($1) { $0.append($1) } }
                        ForEach(order, id: \.self) { key in
                            let items = groups[key] ?? []
                            Section("\(items[0].software.name) \(items[0].software.version)") {
                                ForEach(items) { f in FindingRow(finding: f).tag(f.id) }
                            }
                        }
                    }
                    .frame(minWidth: 340)
                    Group {
                        if let f = findings.first(where: { $0.id == selected }) {
                            FindingDetail(finding: f)
                        } else {
                            ContentUnavailableView("Hinweis auswählen", systemImage: "sidebar.left")
                        }
                    }
                    .frame(minWidth: 380, maxWidth: .infinity, maxHeight: .infinity)
                }
                .searchable(text: $search, prompt: "Programm, Titel oder CVE")
            }
        } else {
            EmptyReportView()
        }
    }
}

struct FindingRow: View {
    let finding: Finding

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                SeverityBadge(severity: finding.effectiveSeverity)
                if !finding.exploited.isEmpty { KEVBadge() }
                if finding.isUncertain { UncertainBadge() }
                Spacer()
                SourceBadge(source: finding.advisory.origin)
                Text(finding.advisory.id).font(.caption).foregroundStyle(.secondary)
            }
            Text(finding.advisory.title).lineLimit(2)
            Text(finding.fixedVersions.isEmpty ? "Keine Fix-Version angegeben" : "Behoben in \(finding.fixedVersions.joined(separator: ", "))")
                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
        }
        .padding(.vertical, 3)
        .opacity(finding.isUncertain ? 0.65 : 1)
    }
}

struct FindingDetail: View {
    let finding: Finding

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 6) {
                    SeverityBadge(severity: finding.effectiveSeverity)
                    if !finding.exploited.isEmpty { KEVBadge() }
                    SourceBadge(source: finding.advisory.origin)
                    if let score = finding.advisory.cvssScore {
                        Text("CVSS \(score, specifier: "%.1f")").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Text(finding.advisory.title).font(.title2.weight(.semibold)).textSelection(.enabled)

                if let reason = finding.uncertainReason {
                    GroupBox {
                        Label {
                            Text(reason).frame(maxWidth: .infinity, alignment: .leading)
                        } icon: {
                            Image(systemName: "questionmark.diamond").foregroundStyle(.orange)
                        }
                    } label: {
                        Text("Unsicherer Treffer – bitte manuell prüfen").bold()
                    }
                }

                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                    GridRow { Text("Installiert").foregroundStyle(.secondary); Text("\(finding.software.name) \(finding.software.version)") }
                    GridRow { Text("Betroffen").foregroundStyle(.secondary); Text(finding.matchedRange).monospaced() }
                    GridRow {
                        Text("Behoben in").foregroundStyle(.secondary)
                        Text(finding.fixedVersions.isEmpty ? "keine Angabe" : finding.fixedVersions.joined(separator: ", "))
                    }
                    GridRow { Text("Zuordnung").foregroundStyle(.secondary); Text(finding.confidence.label) }
                    if let d = finding.advisory.updated {
                        GridRow { Text("Aktualisiert").foregroundStyle(.secondary); Text(d.formatted(date: .abbreviated, time: .omitted)) }
                    }
                    if let path = finding.software.path {
                        GridRow { Text("Pfad").foregroundStyle(.secondary); Text(path).lineLimit(1).truncationMode(.middle) }
                    }
                }
                .textSelection(.enabled)

                if let summary = finding.advisory.summary {
                    GroupBox("Beschreibung (\(finding.advisory.origin.label))") {
                        Text(summary).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                    }
                }

                HStack {
                    if finding.advisory.origin == .bsi {
                        if let url = finding.advisory.portalURL { Link("BSI-Hinweis öffnen", destination: url) }
                        Link("CSAF-Dokument", destination: finding.advisory.csafURL)
                    } else if let url = finding.advisory.portalURL {
                        Link("NVD-Eintrag öffnen", destination: url)
                    }
                }

                if !finding.exploited.isEmpty {
                    GroupBox("Aktiv ausgenutzt (CISA KEV)") {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(finding.exploited, id: \.cveID) { k in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("\(k.cveID) – \(k.vulnerabilityName)").bold()
                                    Text(k.shortDescription).font(.callout).foregroundStyle(.secondary)
                                    if k.usedInRansomware { Text("Wird von Ransomware genutzt").font(.caption).foregroundStyle(.red) }
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }

                GroupBox("CVEs (\(finding.advisory.cves.count))") {
                    let exploited = Set(finding.exploited.map(\.cveID))
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), alignment: .leading)], alignment: .leading, spacing: 4) {
                        ForEach(finding.advisory.cves, id: \.self) { cve in
                            Link(cve, destination: URL(string: "https://nvd.nist.gov/vuln/detail/\(cve)")!)
                                .font(.callout.monospaced())
                                .foregroundStyle(exploited.contains(cve) ? .red : .accentColor)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

// MARK: - CVE list

struct CVEListView: View {
    @Environment(ScanModel.self) private var model
    @State private var filter: CVEStatus?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                if let name = model.watchlistFileName ?? (model.watchlist != nil ? "Gespeicherte Liste" : nil) {
                    Label("\(name) – \(model.watchlist?.cves.count ?? 0) CVEs", systemImage: "doc.text")
                } else {
                    Text("Keine CVE-Liste geladen").foregroundStyle(.secondary)
                }
                Spacer()
                Picker("Filter", selection: $filter) {
                    Text("Alle").tag(CVEStatus?.none)
                    ForEach(CVEStatus.allCases, id: \.self) { Text($0.label).tag(CVEStatus?.some($0)) }
                }
                .pickerStyle(.menu)
                .fixedSize()
                Button("Importieren …") { model.importWatchlistWithPanel() }
                if model.watchlist != nil {
                    Button("Entfernen", role: .destructive) { model.clearWatchlist() }
                }
            }
            .padding(12)
            Divider()

            if let results = model.report?.cveResults, model.watchlist != nil {
                let shown = results.filter { filter == nil || $0.status == filter }
                Table(shown) {
                    TableColumn("CVE") { r in
                        if let url = r.nvdURL { Link(r.cve, destination: url).monospaced() } else { Text(r.cve) }
                    }
                    .width(min: 130, ideal: 150)
                    TableColumn("Status") { r in
                        HStack(spacing: 6) {
                            Label(r.status.label, systemImage: r.status.icon).foregroundStyle(r.status.color)
                            if r.kev != nil { Image(systemName: "flame.fill").foregroundStyle(.red).help("Aktiv ausgenutzt (CISA KEV)") }
                        }
                        .help(r.summary ?? "")
                    }
                    TableColumn("CVSS") { r in
                        Text(r.cvssScore.map { String(format: "%.1f", $0) } ?? "–").monospacedDigit().foregroundStyle(.secondary)
                    }
                    .width(min: 40, ideal: 50)
                    .width(min: 170, ideal: 200)
                    TableColumn("Software") { r in Text(r.software.joined(separator: ", ")).lineLimit(2) }
                    TableColumn("Betroffener Bereich") { r in Text(r.matchedRanges.joined(separator: ", ")).lineLimit(2).foregroundStyle(.secondary) }
                    TableColumn("Quelle") { r in
                        HStack {
                            ForEach(r.advisories.prefix(3), id: \.id) { a in
                                if let url = a.url { Link(a.id, destination: url).help(a.title) } else { Text(a.id) }
                            }
                            if r.advisories.count > 3 { Text("+\(r.advisories.count - 3)").foregroundStyle(.secondary) }
                        }
                    }
                }
            } else if model.watchlist != nil {
                ContentUnavailableView {
                    Label("Liste noch nicht geprüft", systemImage: "list.bullet.rectangle")
                } actions: {
                    Button("Scan starten") { model.startScan() }.disabled(model.isScanning)
                }
            } else {
                ContentUnavailableView {
                    Label("CVE-Liste prüfen", systemImage: "doc.text.magnifyingglass")
                } description: {
                    Text("Importiere eine Textdatei mit einer CVE-ID pro Zeile (z. B. aus einer BSI-Warnmeldung). Zeilen mit # werden ignoriert. Du kannst die Datei auch einfach ins Fenster ziehen.\n\nFür jede CVE zeigt CVEScout, ob installierte Software betroffen ist, bereits gepatcht ist oder das Produkt nicht installiert ist.")
                } actions: {
                    Button("CVE-Liste importieren …") { model.importWatchlistWithPanel() }
                        .buttonStyle(.borderedProminent)
                }
            }
        }
    }
}

// MARK: - Software

struct SoftwareView: View {
    @Environment(ScanModel.self) private var model
    @State private var search = ""
    @State private var onlyMapped = false

    var body: some View {
        if let report = model.report {
            let mapped = Set(report.mappedSoftwareIDs)
            let vulnerable = Set(report.findings.map(\.software.id))
            let items = report.inventory.filter {
                (search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) || $0.identifier.localizedCaseInsensitiveContains(search))
                    && (!onlyMapped || mapped.contains($0.id))
            }
            Table(items) {
                TableColumn("Name") { item in
                    HStack(spacing: 6) {
                        Image(systemName: vulnerable.contains(item.id) ? "exclamationmark.triangle.fill"
                              : mapped.contains(item.id) ? "checkmark.circle" : "circle.dotted")
                            .foregroundStyle(vulnerable.contains(item.id) ? .orange : mapped.contains(item.id) ? .green : .secondary)
                        Text(item.name)
                    }
                }
                TableColumn("Version") { Text($0.version).monospacedDigit() }.width(min: 90, ideal: 120)
                TableColumn("Quelle") { Text($0.source.label) }.width(min: 80, ideal: 100)
                TableColumn("Kennung") { Text($0.identifier).foregroundStyle(.secondary) }
                TableColumn("Status") { item in
                    let n = report.findings(for: item).count
                    Text(n > 0 ? "\(n) Hinweise" : mapped.contains(item.id) ? "keine bekannten Lücken" : "nicht zugeordnet")
                        .foregroundStyle(n > 0 ? .orange : .secondary)
                }
            }
            .searchable(text: $search, prompt: "Software suchen")
            .toolbar {
                ToolbarItem {
                    Toggle("Nur zugeordnete", isOn: $onlyMapped)
                        .help("Nur Software anzeigen, für die eine BSI-Produktzuordnung existiert")
                }
            }
        } else {
            EmptyReportView()
        }
    }
}

// MARK: - Checks

struct ChecksView: View {
    @Environment(ScanModel.self) private var model

    var body: some View {
        if let report = model.report, !report.checks.isEmpty {
            List(report.checks) { check in
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: check.status.icon)
                        .foregroundStyle(check.status.color)
                        .font(.title2)
                        .frame(width: 28)
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(check.title).font(.headline)
                            Spacer()
                            Text(check.status.label).font(.caption).foregroundStyle(check.status.color)
                        }
                        Text(check.detail).foregroundStyle(.secondary).textSelection(.enabled)
                        if let rec = check.recommendation, check.status != .pass {
                            Text(.init("Empfehlung: " + rec)).font(.callout)
                        }
                    }
                }
                .padding(.vertical, 6)
            }
        } else {
            EmptyReportView()
        }
    }
}

// MARK: - Settings

struct SettingsView: View {
    @Environment(ScanModel.self) private var model
    @State private var cacheCleared = false

    var body: some View {
        @Bindable var model = model
        Form {
            Picker("BSI-Hinweise berücksichtigen", selection: $model.lookbackDays) {
                Text("1 Jahr").tag(365)
                Text("2 Jahre").tag(730)
                Text("3 Jahre").tag(1095)
                Text("5 Jahre").tag(1825)
            }
            Toggle("Programme in /Applications prüfen", isOn: $model.includeApplications)
            Toggle("Homebrew-Pakete prüfen", isOn: $model.includeHomebrew)
            Section {
                Toggle("NVD als zweite Quelle nutzen", isOn: $model.useNVD)
                SecureField("NVD-API-Schlüssel (optional)", text: $model.nvdAPIKey)
                    .disabled(!model.useNVD)
            } footer: {
                Text("Die NVD ergänzt Programme, die das BSI nicht abdeckt, und CVEs ohne BSI-Hinweis. Ohne Schlüssel erlaubt die NVD 5 Abfragen pro 30 s – der erste Scan dauert dann etwa eine Minute. Den kostenlosen Schlüssel gibt es unter nvd.nist.gov/developers; er wird im Schlüsselbund gespeichert.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Section {
                HStack {
                    Button("Daten neu laden und scannen") { model.startScan(forceRefresh: true) }
                        .disabled(model.isScanning)
                    Button(cacheCleared ? "Cache geleert" : "Cache leeren") {
                        try? DataCache().clear()
                        cacheCleared = true
                    }
                }
            } footer: {
                Text("BSI-Feed wird 6 h, NVD und CISA KEV 24 h zwischengespeichert (~/Library/Caches/CVEScout).")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 500)
        .padding()
    }
}
