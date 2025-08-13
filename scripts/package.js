#!/usr/bin/env node

/**
 * Package Script for XDR on Edge Extension
 * Creates distributable zip files for Chrome, Firefox, and Edge
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const browsers = ['chrome', 'firefox', 'edge'];
const rootDir = path.resolve(__dirname, '..');
const packagesDir = path.join(rootDir, 'packages');

// Ensure packages directory exists
if (!fs.existsSync(packagesDir)) {
  fs.mkdirSync(packagesDir, { recursive: true });
}

// Read package.json for version
const packageJson = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
const version = packageJson.version;

console.log('📦 Creating distribution packages...\n');

browsers.forEach(browser => {
  const distDir = `dist-${browser}`;
  const distPath = path.join(rootDir, distDir);
  
  if (!fs.existsSync(distPath)) {
    console.log(`❌ ${browser}: Distribution directory not found. Run npm run build:${browser} first.`);
    return;
  }
  
  const zipName = `xdr-on-edge-${browser}-v${version}.zip`;
  const zipPath = path.join(packagesDir, zipName);
  
  try {
    // Remove existing zip if it exists
    if (fs.existsSync(zipPath)) {
      fs.unlinkSync(zipPath);
    }
    
    // Create zip file
    process.chdir(distPath);
    execSync(`zip -r "${zipPath}" .`, { stdio: 'inherit' });
    
    console.log(`✅ ${browser}: Created ${zipName}`);
  } catch (error) {
    console.error(`❌ ${browser}: Failed to create package - ${error.message}`);
  }
});

// Reset working directory
process.chdir(rootDir);

console.log('\n📦 Packaging complete!');
console.log(`📁 Packages created in: ${packagesDir}`);
console.log('\n🚀 Ready for distribution to browser stores!');
