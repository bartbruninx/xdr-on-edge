#!/bin/bash

echo "Building Chrome extension..."
BUILD_TARGET=chrome npx vite build
node scripts/removeInlineScript.cjs dist-chrome
cp manifests/manifest.chrome.json dist-chrome/manifest.json
cp node_modules/webextension-polyfill/dist/browser-polyfill.js dist-chrome/
echo "✅ Chrome build complete in dist-chrome/"

echo ""
echo "Building Firefox extension..."
BUILD_TARGET=firefox npx vite build
node scripts/removeInlineScript.cjs dist-firefox
cp manifests/manifest.firefox.json dist-firefox/manifest.json
cp node_modules/webextension-polyfill/dist/browser-polyfill.js dist-firefox/
cp src/options.html dist-firefox/
echo "✅ Firefox build complete in dist-firefox/"

echo ""
echo "🎉 Cross-browser build completed successfully!"
echo "Chrome extension: dist-chrome/"
echo "Firefox extension: dist-firefox/"
