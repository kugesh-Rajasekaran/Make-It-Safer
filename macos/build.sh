#!/bin/sh
# Builds "Make-It-Safer Notifier.app" (macOS with the Xcode command line
# tools) and signs it ad hoc, which is enough for your own Mac.
set -eu
cd "$(dirname "$0")"
swift build --package-path Notifier -c release
app="build/Make-It-Safer Notifier.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp Notifier/.build/release/Notifier "$app/Contents/MacOS/Notifier"
cp Notifier/Info.plist "$app/Contents/Info.plist"
codesign --force --sign - "$app"
echo "Built $app"
