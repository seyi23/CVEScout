#!/bin/bash
# Regenerates docs/screenshots/*.png from the demo data (no personal data is shown).
# Requires: build/CVEScout.app (./scripts/build-app.sh) and Screen Recording permission for the terminal.
set -euo pipefail
cd "$(dirname "$0")/.."
APP="$PWD/build/CVEScout.app"
OUT="docs/screenshots"
LANG_CODE="${SCREENSHOT_LANG:-en}"
mkdir -p "$OUT"

window_id() {   # largest on-screen window of the given process
  swift - "$1" <<'SWIFT'
import CoreGraphics
let pid = Int(CommandLine.arguments[1])!
let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] ?? []
let w = list.filter { ($0[kCGWindowOwnerPID as String] as? Int) == pid && ($0[kCGWindowLayer as String] as? Int) == 0 }
    .max { (($0[kCGWindowBounds as String] as? [String: Double])?["Width"] ?? 0) < (($1[kCGWindowBounds as String] as? [String: Double])?["Width"] ?? 0) }
print(w?[kCGWindowNumber as String] ?? 0)
SWIFT
}

for section in overview findings cveList startup; do
  open -n --env CVESCOUT_DEMO=1 --env CVESCOUT_LANG="$LANG_CODE" --env CVESCOUT_DEMO_SECTION="$section" "$APP"
  sleep 4
  PID=$(pgrep -f "$APP/Contents/MacOS/CVEScout" | tail -1)
  screencapture -l "$(window_id "$PID")" -o -x "$OUT/$section.png"
  kill "$PID"; sleep 1
  echo "✔ $OUT/$section.png"
done
