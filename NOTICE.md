# Datenquellen und Hinweise / Data sources and notices

CVEScout verarbeitet ausschließlich öffentlich verfügbare Daten. Die Inhalte gehören den jeweiligen Herausgebern;
CVEScout ist mit keinem von ihnen verbunden und wird von keinem empfohlen oder zertifiziert.

CVEScout only processes publicly available data. All content belongs to its publishers; CVEScout is not
affiliated with, endorsed or certified by any of them.

## BSI – Warn- und Informationsdienst (WID) / CERT-Bund

- Quelle: Bundesamt für Sicherheit in der Informationstechnik (BSI), CSAF-Provider
  <https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json>
- Verwendet werden nur Sicherheitshinweise mit TLP:WHITE (ohne Einschränkung weitergebbar).
- CVEScout ist kein Produkt des BSI. Maßgeblich sind die verlinkten Originalhinweise.

## NIST National Vulnerability Database (NVD)

**This product uses the NVD API but is not endorsed or certified by the NVD.**

- Quelle: <https://nvd.nist.gov/developers>
- Gesendet werden ausschließlich CPE-Produktnamen mit Version (z. B. `cpe:2.3:a:electrum:electrum:4.0.9:…`)
  und CVE-IDs aus einer importierten CVE-Liste. Abschaltbar in den Einstellungen bzw. mit `--no-nvd`.
- Only CPE product names with versions and CVE IDs are sent. Can be disabled (settings / `--no-nvd`).

## CISA Known Exploited Vulnerabilities (KEV) Catalog

- Quelle: Cybersecurity and Infrastructure Security Agency (CISA)
  <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- CVEScout is not endorsed by CISA or the U.S. Government.

## Was CVEScout nicht sendet / What CVEScout never sends

Keine Liste installierter Programme, keine Systemeinstellungen, keine Berichte, keine Kennungen des Geräts
oder der Person. Alle Auswertungen laufen lokal.

No inventory, settings, reports, device or personal identifiers. All analysis runs locally.
