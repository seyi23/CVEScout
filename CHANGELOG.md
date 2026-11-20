# Changelog

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
