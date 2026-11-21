#!/bin/bash
# Packages a release: build/CVEScout.app → dist/ (zip, dmg, CLI tarball, SHA-256 checksums, release notes).
# Usage: VERSION=0.3.0 ./scripts/package-release.sh
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:?VERSION must be set, e.g. VERSION=0.3.0}"
DIST="dist"
rm -rf "$DIST" && mkdir -p "$DIST"

VERSION="$VERSION" ./scripts/build-app.sh

# Optional notarization (needs a Developer ID signature, see SIGN_IDENTITY in build-app.sh):
#   NOTARIZE=1 APPLE_ID=… APPLE_TEAM_ID=… APPLE_APP_PASSWORD=… (app-specific password)
NOTARIZED=0
if [ "${NOTARIZE:-0}" = "1" ]; then
  : "${APPLE_ID:?}" "${APPLE_TEAM_ID:?}" "${APPLE_APP_PASSWORD:?}"
  SUBMIT="$(mktemp -d)/CVEScout.zip"
  ditto -c -k --keepParent build/CVEScout.app "$SUBMIT"
  xcrun notarytool submit "$SUBMIT" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD" --wait
  xcrun stapler staple build/CVEScout.app
  spctl --assess --type execute --verbose build/CVEScout.app
  NOTARIZED=1
fi

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

1. Open `CVEScout-<version>.dmg` and drag CVEScout to *Applications* (or unzip `CVEScout-<version>.zip`).
   `CVEScout-<version>.dmg` öffnen und CVEScout in den Ordner *Programme* ziehen.
NOTES
  if [ "$NOTARIZED" = "1" ]; then
    echo "2. Signed with Developer ID and notarized by Apple. / Mit Developer ID signiert und von Apple notarisiert."
  else
    cat <<'NOTES'
2. This build is not notarized by Apple. On first launch allow it under **System Settings › Privacy & Security ›
   “Open Anyway”**. / Nicht notarisiert: beim ersten Start unter **Systemeinstellungen › Datenschutz & Sicherheit ›
   „Trotzdem öffnen“** freigeben.
NOTES
  fi
  cat <<'NOTES'
3. Checksums / Prüfsummen: `shasum -a 256 -c SHA256SUMS.txt`
4. Command line tool / Kommandozeile: `cvescout-cli-<version>-macos.tar.gz` (also inside the app:
   `CVEScout.app/Contents/Resources/cvescout`).

*This product uses the NVD API but is not endorsed or certified by the NVD.*
NOTES
} > "$DIST/RELEASE_NOTES.md"

echo "✔ Release $VERSION in $DIST/:"
ls -1 "$DIST"
