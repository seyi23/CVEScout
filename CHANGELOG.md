# Changelog

## 1.0.0 – 2026-11-21

Erste öffentliche Version. / First public release.

- **Autostart-Objekte:** Launch-Agents und -Daemons mit Signaturprüfung über das Security-Framework (Apple,
  Developer ID, App Store, ad-hoc, nicht signiert, ungültig), Skripte über Interpreter, verwaiste Einträge,
  ungewöhnliche Orte. Eigener Bereich „Autostart & Add-ons“ mit „Im Finder zeigen“.
- **Browser-Erweiterungen:** Chrome, Brave, Edge, Vivaldi, Arc, Chromium, Firefox, Safari – mit Zugriff auf alle
  Webseiten und weitreichenden Rechten (nativeMessaging, debugger, proxy, cookies …).
- **Mitteilungen** auch bei neuen Autostart-Objekten und neuen Browser-Erweiterungen.
- **Signierung & Notarisierung vorbereitet:** `SIGN_IDENTITY` (Hardened Runtime) und `NOTARIZE=1`; der
  Release-Workflow signiert und notarisiert automatisch, sobald die Secrets hinterlegt sind.
- **Demo-Modus** (`CVESCOUT_DEMO=1`) und `scripts/screenshots.sh` für reproduzierbare Screenshots ohne persönliche Daten.
- Erster Eintrag der Schwachstellen-Liste wird automatisch ausgewählt; einheitliche Kachelhöhen in der Übersicht.

## 0.4.0 – 2026-11-21

- **Englische Oberfläche:** App, Menüleiste, Mitteilungen, CLI und Berichte gibt es auf Deutsch und Englisch.
  Die Sprache folgt dem System (andere Sprachen → Englisch) und lässt sich in den Einstellungen umstellen
  (mit „Jetzt neu starten“) bzw. per `--lang de|en` oder `CVESCOUT_LANG`. Datumsangaben und Systemmenüs folgen
  der gewählten Sprache. Titel und Zusammenfassungen der BSI-Hinweise bleiben deutsch (Originaldaten).

- MIT-Lizenz, `NOTICE.md` mit Datenquellen, Datenschutzangaben und dem von der NVD geforderten Hinweis
  (auch in App, CLI-Hilfe und Markdown-Bericht).
- Bundle-ID `io.github.seyi23.cvescout`, im Build-Skript per `BUNDLE_ID` überschreibbar.
- GitHub Actions: Build, Tests und App-Bundle als Artefakt bei jedem Push/PR.
- Automatische Releases bei Tag `v*`: zip, dmg, CLI-Archiv, SHA-256-Prüfsummen, Release-Notes aus dem CHANGELOG
  (`scripts/package-release.sh`).
- App-Icon (Schild mit Lupe), reproduzierbar erzeugt mit `scripts/make-icon.swift`.
- README auf Englisch (Hauptsprache) und Deutsch, CONTRIBUTING, SECURITY, Issue-Vorlagen (Fehlalarm,
  fehlende Software, Fehler) und Pull-Request-Vorlage.

## 0.3.0 – 2026-11-21

- **Menüleisten-Modus:** Schild-Symbol in der Menüleiste zeigt den Status (grün/orange/rot), ein Klick öffnet
  ein Panel mit Kennzahlen, den betroffenen Programmen und Schnellaktionen. Die App läuft nach dem Schließen
  des Fensters weiter; das Dock-Symbol lässt sich ausblenden.
- **Hintergrund-Scan:** automatisch alle 6 h, 12 h, täglich (Standard) oder wöchentlich; nach Ruhezustand wird
  ein fälliger Scan nachgeholt, bei fehlender Verbindung nach 15 Minuten erneut versucht.
- **Mitteilungen** nur bei *neuen* bestätigten Funden oder neu auffälligen Einstellungen (Vergleich mit dem
  vorherigen Scan); aktiv ausgenutzte Lücken werden im Titel hervorgehoben.
- **Beim Anmelden starten** (SMAppService).

## 0.2.1 – 2026-11-21

- **Fehlzuordnung behoben:** BSI-Hinweis WID-SEC-W-2025-2158 (CVE-2025-56449) betrifft „Obsidian Scheduler“,
  nicht die Notiz-App Obsidian. Bekannte Fehlzuordnungen des BSI werden jetzt übersprungen und im Bericht genannt.
- **Plausibilitätsprüfung:** Treffer, bei denen die installierte Version weit unter allen im Hinweis genannten
  Versionen liegt (anderes Produkt gleichen Namens) oder der Hinweis keine Fix-Version nennt, werden als
  *unsicher* markiert, getrennt angezeigt und nicht in den Kennzahlen gezählt.
- Datenfehler im BSI-Feed abgefangen: Commit-Hashes als „Fix-Version“, „=>1.11“, Fix-Versionen innerhalb des
  betroffenen Bereichs.

## 0.2.0 – 2026-11-21

- **NVD als zweite Quelle:** Programme ohne BSI-Abdeckung werden über kuratierte CPE-Namen bei der NVD geprüft
  (30 Zuordnungen, u. a. Discord, Telegram, Signal, 1Password, Brave, iTerm2, Little Snitch, Ledger Live, Electrum).
  Plattform-Filter für Windows-/Android-/iOS-Konfigurationen, Rate-Limiting, 24-h-Cache, optionaler API-Schlüssel
  (Schlüsselbund bzw. `NVD_API_KEY`).
- **CVE-Liste:** CVEs ohne BSI-Hinweis werden in der NVD nachgeschlagen (Status, CVSS, Beschreibung).
  Status „Gepatcht“ heißt jetzt „Nicht betroffen“, „Kein BSI-Hinweis“ heißt „Keine Daten“.
- **Neue Systemprüfung:** ausstehende Apple-Updates (`softwareupdate --list`).
- Homebrew-Pakete werden automatisch BSI-„Open Source“-Produkten zugeordnet; FileZilla ergänzt.
- App: Quellen-Badges (BSI/NVD), CVSS-Werte, NVD-Einstellungen; CLI: `--no-nvd`.

## 0.1.0 – 2026-11-20

- Erste Version: Inventar (macOS, Programme, Homebrew), Abgleich mit BSI-WID-CSAF, CISA KEV,
  Systemprüfungen, CVE-Liste aus TXT-Datei, Export (Markdown/JSON), SwiftUI-App und CLI.
