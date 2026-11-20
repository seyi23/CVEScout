# Changelog

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
