const fs = require('fs');
const path = require('path');
const glob = require('glob');

function hash(value) {
  let hash = 5381;
  let i = value.length;
  if (typeof value === "string") {
    while (i) hash = (hash * 33) ^ value.charCodeAt(--i);
  } else {
    while (i) hash = (hash * 33) ^ value[--i];
  }
  return (hash >>> 0).toString(36);
}

async function removeInlineScript(directory) {
  console.log("Removing Inline Scripts...");
  
  const files = glob.sync("**/*.html", {
    cwd: directory,
    absolute: false
  });

  files.forEach(file => {
    const filePath = path.join(directory, file);
    let content = fs.readFileSync(filePath, 'utf8');
    
    // More specific regex to match script tags with inline content
    const scriptRegx = /<script(?![^>]*src=)([^>]*)>([\s\S]*?)<\/script>/g;
    let match;
    let hasChanges = false;
    
    while ((match = scriptRegx.exec(content)) !== null) {
      const fullMatch = match[0];
      const attributes = match[1];
      const scriptContent = match[2].trim();
      
      // Skip if script is empty or just whitespace
      if (!scriptContent) {
        continue;
      }
      
      // Generate filename for the extracted script
      const scriptHash = hash(scriptContent);
      const scriptFileName = `script-${scriptHash}.js`;
      const scriptPath = path.join(directory, scriptFileName);
      
      // Write the script content to a separate file
      fs.writeFileSync(scriptPath, scriptContent);
      
      // Replace inline script with external script reference
      const newScriptTag = `<script${attributes} src="./${scriptFileName}"></script>`;
      content = content.replace(fullMatch, newScriptTag);
      hasChanges = true;
      
      console.log(`Extracted inline script to: ${scriptFileName}`);
    }
    
    // Write the modified HTML back if there were changes
    if (hasChanges) {
      fs.writeFileSync(filePath, content);
      console.log(`Updated: ${file}`);
    }
  });
  
  console.log("Inline script removal completed!");
}

// Get the build directory from command line argument or default to 'dist'
const buildDir = process.argv[2] || 'dist';
removeInlineScript(path.resolve(__dirname, '..', buildDir));
