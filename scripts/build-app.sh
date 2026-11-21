#!/bin/bash
# Builds CVEScout.app (release, ad-hoc signed) into ./build
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-0.3.0}"
# Reverse-DNS identifier; override for forks: BUNDLE_ID=io.github.<user>.cvescout ./scripts/build-app.sh
BUNDLE_ID="${BUNDLE_ID:-io.github.seyi23.cvescout}"
APP="build/CVEScout.app"

swift build -c release --product CVEScoutApp
swift build -c release --product cvescout
BIN="$(swift build -c release --show-bin-path)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN/CVEScoutApp" "$APP/Contents/MacOS/CVEScout"
cp "$BIN/cvescout" "$APP/Contents/Resources/cvescout"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>CVEScout</string>
    <key>CFBundleDisplayName</key><string>CVEScout</string>
    <key>CFBundleIdentifier</key><string>${BUNDLE_ID}</string>
    <key>CFBundleExecutable</key><string>CVEScout</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>${VERSION}</string>
    <key>CFBundleVersion</key><string>${VERSION}</string>
    <key>LSMinimumSystemVersion</key><string>14.0</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSHumanReadableCopyright</key><string>© 2026 seyi23 · MIT-Lizenz</string>
</dict>
</plist>
PLIST

codesign --force --deep --sign - "$APP"
echo "✔ $APP gebaut (Version $VERSION, $BUNDLE_ID)"
