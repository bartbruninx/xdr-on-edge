const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Build script for cross-browser extension
async function buildCrossBrowser() {
  const browsers = ['chrome', 'firefox'];
  
  console.log('🚀 Starting cross-browser extension build...');
  
  for (const browser of browsers) {
    const browserDir = `dist-${browser}`;
    
    console.log(`\n📦 Building for ${browser}...`);
    
    // Clean existing browser-specific directory
    if (fs.existsSync(browserDir)) {
      fs.rmSync(browserDir, { recursive: true, force: true });
      console.log(`   🧹 Cleaned existing ${browser} build directory`);
    }
    
    // Run browser-specific build command
    try {
      console.log(`   ⚡ Running npm run build:${browser}...`);
      execSync(`npm run build:${browser}`, { 
        stdio: 'inherit',
        cwd: process.cwd()
      });
      console.log(`   ✅ ${browser.charAt(0).toUpperCase() + browser.slice(1)} build complete!`);
    } catch (error) {
      console.error(`   ❌ Failed to build for ${browser}:`, error.message);
      process.exit(1);
    }
  }
  
  console.log(`\n🎉 Cross-browser build complete!`);
  console.log(`📁 Chrome build: dist-chrome/`);
  console.log(`📁 Firefox build: dist-firefox/`);
  console.log(`\n📋 Next steps:`);
  console.log(`   • Chrome: Load unpacked extension from dist-chrome/`);
  console.log(`   • Firefox: Load temporary add-on from dist-firefox/`);
}

buildCrossBrowser().catch(console.error);
