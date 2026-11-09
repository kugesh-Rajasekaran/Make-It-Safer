#!/bin/sh
# Builds "Make-It-Safer Notifier.app" (macOS with the Xcode command line
# tools) and signs it ad hoc, which is enough for your own Mac.
# UNIVERSAL=1 builds one app for both Apple Silicon and Intel (releases).
set -eu
cd "$(dirname "$0")"
if [ "${UNIVERSAL:-}" = 1 ]; then
	swift build --package-path Notifier -c release --arch arm64 --arch x86_64
	bin=Notifier/.build/apple/Products/Release/Notifier
else
	swift build --package-path Notifier -c release
	bin=Notifier/.build/release/Notifier
fi
app="build/Make-It-Safer Notifier.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp "$bin" "$app/Contents/MacOS/Notifier"
cp Notifier/Info.plist "$app/Contents/Info.plist"
codesign --force --sign - "$app"
echo "Built $app"
