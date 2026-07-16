#!/bin/bash
#
# build.sh - Compile Web Scanner and package it into a macOS .app bundle.
#
# Usage:
#   ./build.sh            Build a release .app bundle
#   ./build.sh --run      Build, then launch the app
#   ./build.sh --debug    Build a debug binary (faster compile)
#
set -euo pipefail

# Always operate from the directory that contains this script.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

APP_NAME="WebScanner"
DISPLAY_APP="WebScanner.app"
CONFIG="release"
DO_RUN=0

for arg in "$@"; do
	case "$arg" in
		--run)   DO_RUN=1 ;;
		--debug) CONFIG="debug" ;;
		--help|-h)
			echo "Usage: ./build.sh [--run] [--debug]"
			exit 0
			;;
		*) echo "Unknown option: $arg" >&2; exit 1 ;;
	esac
done

echo "==> Checking toolchain"
if ! command -v swift >/dev/null 2>&1; then
	echo "ERROR: 'swift' not found. Install Xcode Command Line Tools:" >&2
	echo "       xcode-select --install" >&2
	exit 1
fi
swift --version | head -n 1

echo "==> Compiling ($CONFIG)"
swift build -c "$CONFIG" --product "$APP_NAME"

BIN_PATH="$(swift build -c "$CONFIG" --product "$APP_NAME" --show-bin-path)/$APP_NAME"
if [[ ! -f "$BIN_PATH" ]]; then
	echo "ERROR: Build succeeded but binary not found at: $BIN_PATH" >&2
	exit 1
fi

echo "==> Assembling $DISPLAY_APP"
rm -rf "$DISPLAY_APP"
mkdir -p "$DISPLAY_APP/Contents/MacOS"
mkdir -p "$DISPLAY_APP/Contents/Resources"

cp "$BIN_PATH" "$DISPLAY_APP/Contents/MacOS/$APP_NAME"
cp "Resources/Info.plist" "$DISPLAY_APP/Contents/Info.plist"

if [[ -f "Resources/AppIcon.icns" ]]; then
	cp "Resources/AppIcon.icns" "$DISPLAY_APP/Contents/Resources/AppIcon.icns"
fi

echo "==> Code signing (ad-hoc)"
# Ad-hoc signing lets the app run locally without a Developer ID.
codesign --force --deep --sign - "$DISPLAY_APP" >/dev/null 2>&1 || \
	echo "   (ad-hoc signing skipped/failed - app will still run)"

echo ""
echo "✅ Built: $SCRIPT_DIR/$DISPLAY_APP"
echo "   Launch with:  open \"$DISPLAY_APP\""
echo ""

if [[ "$DO_RUN" -eq 1 ]]; then
	echo "==> Launching"
	open "$DISPLAY_APP"
fi
