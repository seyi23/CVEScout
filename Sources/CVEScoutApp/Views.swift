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
                        StatTile(title: tr("Betroffene Programme", "Affected apps"), value: report.vulnerableSoftwareCount,
                                 tint: report.vulnerableSoftwareCount > 0 ? .orange : .green) { selection = .findings }
                        StatTile(title: tr("Zutreffende Hinweise (BSI/NVD)", "Matching advisories (BSI/NVD)"), value: report.confirmedFindings.count,
                                 tint: report.confirmedFindings.isEmpty ? .green : .orange) { selection = .findings }
                        if !report.uncertainFindings.isEmpty {
                            StatTile(title: tr("Unsichere Treffer (prüfen)", "Uncertain matches (check)"), value: report.uncertainFindings.count,
                                     tint: .secondary) { selection = .findings }
                        }
                        StatTile(title: tr("Aktiv ausgenutzte CVEs", "Actively exploited CVEs"), value: report.exploitedCount,
                                 tint: report.exploitedCount > 0 ? .red : .green) { selection = .findings }
                        let problems = report.checks.filter { $0.status == .fail || $0.status == .warning }.count
                        StatTile(title: tr("Auffällige Einstellungen", "Settings needing attention"), value: problems,
                                 tint: problems > 0 ? .orange : .green) { selection = .checks }
                        if let results = report.cveResults {
                            let hit = results.filter { $0.status == .affected }.count
                            StatTile(title: tr("CVE-Liste: betroffen", "CVE list: affected"), value: hit,
                                     subtitle: tr("von \(results.count)", "of \(results.count)"),
                                     tint: hit > 0 ? .red : .green) { selection = .cveList }
                        }
                    }
                    severityBreakdown(report)
                    sources(report)
                    if !report.warnings.isEmpty {
                        GroupBox(tr("Hinweise", "Notes")) {
                            VStack(alignment: .leading, spacing: 4) {
                                ForEach(report.warnings, id: \.self) { Text("• " + $0) }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text(tr("CVEScout vergleicht Versionsnummern mit veröffentlichten Sicherheitshinweisen. Es werden keine Exploits ausgeführt. Ergebnisse ohne Gewähr – Details stehen jeweils im verlinkten Originalhinweis.", "CVEScout compares version numbers with published security advisories. No exploits are run. Results without warranty – details are in the linked original advisories."))
                        Text(DataSources.attribution)
                    }
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
                Text(tr("Letzter Scan: \(report.date.formatted(Date.FormatStyle(date: .abbreviated, time: .shortened).locale(Language.current.locale)))", "Last scan: \(report.date.formatted(Date.FormatStyle(date: .abbreviated, time: .shortened).locale(Language.current.locale)))"))
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }

    private func severityBreakdown(_ report: ScanReport) -> some View {
        GroupBox(tr("Schweregrade", "Severities")) {
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
        GroupBox(tr("Datenbasis", "Data")) {
            Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                GridRow {
                    Text(tr("Erfasste Software", "Software found")).foregroundStyle(.secondary)
                    Text(tr("\(report.inventory.count), davon \(report.mappedSoftwareIDs.count) mit BSI-Zuordnung", "\(report.inventory.count), \(report.mappedSoftwareIDs.count) of them mapped"))
                }
                GridRow {
                    Text("BSI WID/CERT-Bund").foregroundStyle(.secondary)
                    Text(tr("\(report.advisoriesEvaluated) Hinweise ausgewertet", "\(report.advisoriesEvaluated) advisories evaluated")
                         + (report.bsiFeedDate.map { tr(", Stand ", ", as of ") + $0.formatted(Date.FormatStyle(date: .abbreviated, time: .shortened).locale(Language.current.locale)) } ?? ""))
                }
                GridRow {
                    Text("NIST NVD").foregroundStyle(.secondary)
                    let n = report.confirmedFindings.filter { $0.advisory.origin == .nvd }.count
                    Text(model.useNVD ? tr("\(n) zutreffende CVEs (für Programme ohne BSI-Abdeckung)", "\(n) matching CVE\(n == 1 ? "" : "s") (for apps without BSI coverage)") : tr("deaktiviert", "disabled"))
                }
                GridRow {
                    Text("CISA KEV").foregroundStyle(.secondary)
                    Text(report.kevCatalogVersion.map { tr("Katalog \($0)", "Catalog \($0)") } ?? tr("nicht verfügbar", "not available"))
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
                Text(title).font(.callout).foregroundStyle(.secondary).lineLimit(2, reservesSpace: true)
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
                ContentUnavailableView(tr("Keine bekannten Schwachstellen", "No known vulnerabilities"),
                                       systemImage: "checkmark.shield",
                                       description: Text(tr("Für die erfasste Software liegen keine zutreffenden BSI-Hinweise vor.", "There are no matching advisories for the installed software.")))
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
                            ContentUnavailableView(tr("Hinweis auswählen", "Select an advisory"), systemImage: "sidebar.left")
                        }
                    }
                    .frame(minWidth: 380, maxWidth: .infinity, maxHeight: .infinity)
                }
                .onAppear { if selected == nil { selected = findings.first?.id } }
                .searchable(text: $search, prompt: tr("Programm, Titel oder CVE", "App, title or CVE"))
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
            Text(finding.fixedVersions.isEmpty ? tr("Keine Fix-Version angegeben", "No fixed version given") : tr("Behoben in ", "Fixed in ") + finding.fixedVersions.joined(separator: ", "))
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
                        Text(tr("Unsicherer Treffer – bitte manuell prüfen", "Uncertain match – please check manually")).bold()
                    }
                }

                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
                    GridRow { Text(tr("Installiert", "Installed")).foregroundStyle(.secondary); Text("\(finding.software.name) \(finding.software.version)") }
                    GridRow { Text(tr("Betroffen", "Affected")).foregroundStyle(.secondary); Text(finding.matchedRange).monospaced() }
                    GridRow {
                        Text(tr("Behoben in", "Fixed in")).foregroundStyle(.secondary)
                        Text(finding.fixedVersions.isEmpty ? tr("keine Angabe", "not specified") : finding.fixedVersions.joined(separator: ", "))
                    }
                    GridRow { Text(tr("Zuordnung", "Mapping")).foregroundStyle(.secondary); Text(finding.confidence.label) }
                    if let d = finding.advisory.updated {
                        GridRow { Text(tr("Aktualisiert", "Updated")).foregroundStyle(.secondary); Text(d.formatted(Date.FormatStyle(date: .abbreviated, time: .omitted).locale(Language.current.locale))) }
                    }
                    if let path = finding.software.path {
                        GridRow { Text(tr("Pfad", "Path")).foregroundStyle(.secondary); Text(path).lineLimit(1).truncationMode(.middle) }
                    }
                }
                .textSelection(.enabled)

                if let summary = finding.advisory.summary {
                    GroupBox(tr("Beschreibung (\(finding.advisory.origin.label))", "Description (\(finding.advisory.origin.label))")) {
                        Text(summary).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                    }
                }

                HStack {
                    if finding.advisory.origin == .bsi {
                        if let url = finding.advisory.portalURL { Link(tr("BSI-Hinweis öffnen", "Open BSI advisory"), destination: url) }
                        Link(tr("CSAF-Dokument", "CSAF document"), destination: finding.advisory.csafURL)
                    } else if let url = finding.advisory.portalURL {
                        Link(tr("NVD-Eintrag öffnen", "Open NVD entry"), destination: url)
                    }
                }

                if !finding.exploited.isEmpty {
                    GroupBox(tr("Aktiv ausgenutzt (CISA KEV)", "Actively exploited (CISA KEV)")) {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(finding.exploited, id: \.cveID) { k in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("\(k.cveID) – \(k.vulnerabilityName)").bold()
                                    Text(k.shortDescription).font(.callout).foregroundStyle(.secondary)
                                    if k.usedInRansomware { Text(tr("Wird von Ransomware genutzt", "Used in ransomware campaigns")).font(.caption).foregroundStyle(.red) }
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
                if let name = model.watchlistFileName ?? (model.watchlist != nil ? tr("Gespeicherte Liste", "Saved list") : nil) {
                    Label("\(name) – \(model.watchlist?.cves.count ?? 0) CVEs", systemImage: "doc.text")
                } else {
                    Text(tr("Keine CVE-Liste geladen", "No CVE list loaded")).foregroundStyle(.secondary)
                }
                Spacer()
                Picker("Filter", selection: $filter) {
                    Text(tr("Alle", "All")).tag(CVEStatus?.none)
                    ForEach(CVEStatus.allCases, id: \.self) { Text($0.label).tag(CVEStatus?.some($0)) }
                }
                .pickerStyle(.menu)
                .fixedSize()
                Button(tr("Importieren …", "Import …")) { model.importWatchlistWithPanel() }
                if model.watchlist != nil {
                    Button(tr("Entfernen", "Remove"), role: .destructive) { model.clearWatchlist() }
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
                            if r.kev != nil { Image(systemName: "flame.fill").foregroundStyle(.red).help(tr("Aktiv ausgenutzt (CISA KEV)", "Actively exploited (CISA KEV)")) }
                        }
                        .help(r.summary ?? "")
                    }
                    TableColumn("CVSS") { r in
                        Text(r.cvssScore.map { String(format: "%.1f", $0) } ?? "–").monospacedDigit().foregroundStyle(.secondary)
                    }
                    .width(min: 40, ideal: 50, max: 60)
                    .width(min: 170, ideal: 200)
                    TableColumn("Software") { r in Text(r.software.joined(separator: ", ")).lineLimit(2) }
                    TableColumn(tr("Betroffener Bereich", "Affected range")) { r in Text(r.matchedRanges.joined(separator: ", ")).lineLimit(2).foregroundStyle(.secondary) }
                    TableColumn(tr("Quelle", "Source")) { r in
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
                    Label(tr("Liste noch nicht geprüft", "List not checked yet"), systemImage: "list.bullet.rectangle")
                } actions: {
                    Button(tr("Scan starten", "Start scan")) { model.startScan() }.disabled(model.isScanning)
                }
            } else {
                ContentUnavailableView {
                    Label(tr("CVE-Liste prüfen", "Check a CVE list"), systemImage: "doc.text.magnifyingglass")
                } description: {
                    Text(tr("Importiere eine Textdatei mit einer CVE-ID pro Zeile (z. B. aus einer BSI-Warnmeldung). Zeilen mit # werden ignoriert. Du kannst die Datei auch einfach ins Fenster ziehen.\n\nFür jede CVE zeigt CVEScout, ob installierte Software betroffen ist, bereits gepatcht ist oder das Produkt nicht installiert ist.", "Import a text file with one CVE id per line (for example from a security bulletin). Lines starting with # are ignored. You can also drop the file onto the window.\n\nFor every CVE, CVEScout shows whether installed software is affected, already patched, or whether the product is not installed."))
                } actions: {
                    Button(tr("CVE-Liste importieren …", "Import CVE list …")) { model.importWatchlistWithPanel() }
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
                TableColumn(tr("Quelle", "Source")) { Text($0.source.label) }.width(min: 80, ideal: 100)
                TableColumn(tr("Kennung", "Identifier")) { Text($0.identifier).foregroundStyle(.secondary) }
                TableColumn("Status") { item in
                    let n = report.findings(for: item).count
                    Text(n > 0 ? tr("\(n) Hinweise", "\(n) advisories") : mapped.contains(item.id) ? tr("keine bekannten Lücken", "no known vulnerabilities") : tr("nicht zugeordnet", "not mapped"))
                        .foregroundStyle(n > 0 ? .orange : .secondary)
                }
            }
            .searchable(text: $search, prompt: tr("Software suchen", "Search software"))
            .toolbar {
                ToolbarItem {
                    Toggle(tr("Nur zugeordnete", "Mapped only"), isOn: $onlyMapped)
                        .help(tr("Nur Software anzeigen, für die eine BSI-Produktzuordnung existiert", "Only show software that is mapped to a BSI or NVD product"))
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
                            Text(.init(tr("Empfehlung: ", "Recommendation: ") + rec)).font(.callout)
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
            Section {
                Picker(tr("Sprache", "Language"), selection: $model.appLanguage) {
                    Text(tr("Systemsprache", "System language")).tag("system")
                    Text("Deutsch").tag("de")
                    Text("English").tag("en")
                }
                if model.languageChangePending {
                    HStack {
                        Text(tr("Wird nach einem Neustart wirksam.", "Takes effect after a restart."))
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button(tr("Jetzt neu starten", "Restart now")) { model.relaunch() }
                    }
                }
            }
            Section(tr("Umfang", "Scope")) {
                Picker(tr("BSI-Hinweise berücksichtigen", "Consider BSI advisories from"), selection: $model.lookbackDays) {
                    Text(tr("1 Jahr", "1 year")).tag(365)
                    Text(tr("2 Jahre", "2 years")).tag(730)
                    Text(tr("3 Jahre", "3 years")).tag(1095)
                    Text(tr("5 Jahre", "5 years")).tag(1825)
                }
                Toggle(tr("Programme in /Applications prüfen", "Check apps in /Applications"), isOn: $model.includeApplications)
                Toggle(tr("Homebrew-Pakete prüfen", "Check Homebrew packages"), isOn: $model.includeHomebrew)
            }
            Section {
                Picker(tr("Automatisch scannen", "Scan automatically"), selection: $model.autoScanInterval) {
                    ForEach(AutoScanInterval.allCases) { Text($0.label).tag($0) }
                }
                Toggle(tr("Mitteilung bei neuen Funden", "Notify about new findings"), isOn: $model.notificationsEnabled)
                    .disabled(model.autoScanInterval == .off)
                Toggle(tr("Beim Anmelden starten", "Launch at login"), isOn: $model.launchAtLogin)
                Toggle(tr("Symbol im Dock anzeigen", "Show icon in Dock"), isOn: $model.showDockIcon)
            } header: {
                Text(tr("Hintergrund", "Background"))
            } footer: {
                Text(tr("CVEScout läuft nach dem Schließen des Fensters in der Menüleiste weiter und scannt im gewählten Abstand. Mitteilungen gibt es nur für neue bestätigte Funde und neu auffällige Einstellungen.", "CVEScout keeps running in the menu bar after the window is closed and scans at the chosen interval. You are only notified about new confirmed findings and settings that newly need attention."))
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Section {
                Toggle(tr("NVD als zweite Quelle nutzen", "Use the NVD as a second source"), isOn: $model.useNVD)
                SecureField(tr("NVD-API-Schlüssel (optional)", "NVD API key (optional)"), text: $model.nvdAPIKey)
                    .disabled(!model.useNVD)
            } footer: {
                Text(tr("Die NVD ergänzt Programme, die das BSI nicht abdeckt, und CVEs ohne BSI-Hinweis. Ohne Schlüssel erlaubt die NVD 5 Abfragen pro 30 s – der erste Scan dauert dann etwa eine Minute. Den kostenlosen Schlüssel gibt es unter nvd.nist.gov/developers; er wird im Schlüsselbund gespeichert.", "The NVD covers apps the BSI does not, and CVEs without a BSI advisory. Without a key the NVD allows 5 requests per 30 s, so the first scan takes about a minute. Get a free key at nvd.nist.gov/developers; it is stored in the Keychain."))
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Section {
                HStack {
                    Button(tr("Daten neu laden und scannen", "Reload data and scan")) { model.startScan(forceRefresh: true) }
                        .disabled(model.isScanning)
                    Button(cacheCleared ? tr("Cache geleert", "Cache cleared") : tr("Cache leeren", "Clear cache")) {
                        try? DataCache().clear()
                        cacheCleared = true
                    }
                }
            } footer: {
                Text(tr("BSI-Feed wird 6 h, NVD und CISA KEV 24 h zwischengespeichert (~/Library/Caches/CVEScout).", "The BSI feed is cached for 6 h, NVD and CISA KEV for 24 h (~/Library/Caches/CVEScout)."))
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 520)
        .padding()
    }
}
