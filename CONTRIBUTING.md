# Contributing to CVEScout

Thanks for helping! The most valuable contributions are **catalog entries** and **false-positive reports** –
they directly improve how many apps CVEScout can check and how reliable the results are.

## Development setup

Requirements: macOS 14+, Xcode 26+ (Swift 6.2+).

```bash
swift build                    # build everything
swift test                     # unit tests (offline, fixtures only)
swift run cvescout --help      # CLI
./scripts/build-app.sh         # build/CVEScout.app
```

## Adding software to the catalog

All mappings live in [`Sources/CVEScoutCore/ProductCatalog.swift`](Sources/CVEScoutCore/ProductCatalog.swift).

1. Find the bundle identifier: `mdls -name kMDItemCFBundleIdentifier -r /Applications/<App>.app`
2. **BSI first** – if the BSI feed has the product, add it to `applications` (or `homebrew`) with the exact
   vendor/product spelling used in the BSI CSAF documents.
3. **Otherwise NVD** – add it to `cpeApplications` with the CPE `vendor:product`. Verify it exists:
   `https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:a:<vendor>:<product>`
4. Run a scan and check that the results are plausible for the installed version.

## Reporting false positives

Use the *False positive* issue template. If the advisory is filed under the wrong product (as with
WID-SEC-W-2025-2158, which concerns *Obsidian Scheduler*, not the Obsidian notes app), add it to
`ProductCatalog.misattributedAdvisories` with a short reason.

## Pull requests

- Keep changes focused; add or update tests in `Tests/CVEScoutCoreTests` for matching logic.
- No network access in tests – use JSON fixtures.
- Update `CHANGELOG.md` under *Unveröffentlicht* (unreleased).
- User-facing strings are currently German; English localization is planned.

## Principles

- **Passive only:** no exploit code, no changes to the system, no admin rights.
- **Privacy:** never send inventory, settings or reports anywhere. Only public feeds are downloaded; only
  CPE names with versions and CVE ids are sent to the NVD (see [NOTICE.md](NOTICE.md)).
