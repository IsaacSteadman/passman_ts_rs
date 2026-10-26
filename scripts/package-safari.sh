#!/bin/sh
# Wraps the Safari build of the extension in the Xcode project (a small macOS
# and iOS app) that Safari extensions ship in. Needs macOS with Xcode; then
# open the project, build and run the app, and turn the extension on in
# Safari's settings (Develop → Allow Unsigned Extensions while developing).
set -eu
cd "$(dirname "$0")/.."
[ -d dist-extension/safari ] || npm run build:extension
xcrun safari-web-extension-converter dist-extension/safari \
  --project-location dist-extension/safari-xcode \
  --app-name Passman \
  --bundle-identifier com.firaxite.passman \
  --swift --copy-resources --no-open --force
