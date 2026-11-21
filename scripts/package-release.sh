#!/bin/bash
# Packages a release: build/CVEScout.app → dist/ (zip, dmg, CLI tarball, SHA-256 checksums, release notes).
# Usage: VERSION=0.3.0 ./scripts/package-release.sh
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:?VERSION must be set, e.g. VERSION=0.3.0}"
DIST="dist"
rm -rf "$DIST" && mkdir -p "$DIST"

VERSION="$VERSION" ./scripts/build-app.sh

# App as zip (keeps the bundle structure and signature)
ditto -c -k --keepParent build/CVEScout.app "$DIST/CVEScout-$VERSION.zip"

# App as disk image with a shortcut to /Applications
STAGING="$(mktemp -d)"
cp -R build/CVEScout.app "$STAGING/"
ln -s /Applications "$STAGING/Applications"
hdiutil create -quiet -volname "CVEScout $VERSION" -srcfolder "$STAGING" -ov -format UDZO "$DIST/CVEScout-$VERSION.dmg"
rm -rf "$STAGING"

# Command line tool on its own
tar -czf "$DIST/cvescout-cli-$VERSION-macos.tar.gz" -C build/CVEScout.app/Contents/Resources cvescout

(cd "$DIST" && shasum -a 256 * > SHA256SUMS.txt)

# Release notes: the matching CHANGELOG section plus installation hints.
{
  awk -v v="$VERSION" '
    /^## / { if (found) exit; if (index($0, "## " v " ") == 1 || $0 == "## " v) { found = 1; next } }
    found { print }
  ' CHANGELOG.md
  cat <<'NOTES'

---

### Installation

1. `CVEScout-<version>.dmg` öffnen und CVEScout in den Ordner *Programme* ziehen.
2. Die App ist (noch) nicht von Apple notarisiert. Beim ersten Start meldet macOS deshalb, dass die App
   nicht geprüft werden kann: **Systemeinstellungen › Datenschutz & Sicherheit › „Trotzdem öffnen“**.
3. Prüfsummen stehen in `SHA256SUMS.txt` (`shasum -a 256 -c SHA256SUMS.txt`).

*This product uses the NVD API but is not endorsed or certified by the NVD.*
NOTES
} > "$DIST/RELEASE_NOTES.md"

echo "✔ Release $VERSION in $DIST/:"
ls -1 "$DIST"
