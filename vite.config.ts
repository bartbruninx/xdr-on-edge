import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import path from 'path';

// Get build target from environment variable
const buildTarget = process.env.BUILD_TARGET || 'chrome';
const outDir = buildTarget === 'firefox' ? 'dist-firefox' : buildTarget === 'edge' ? 'dist-edge' : 'dist-chrome';

// https://vite.dev/config/
export default defineConfig({
  plugins: [tailwindcss(), svelte()],
  resolve: {
    alias: {
      $lib: path.resolve(__dirname, './src/lib')
    }
  },
  build: {
    rollupOptions: {
      input: {
        main: 'index.html',
        background: 'src/background.ts',
        options: 'src/options.ts'
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'background') {
            return 'background.js';
          }

          if (chunkInfo.name === 'options') {
            return 'options.js';
          }

          return 'assets/[name].js';
        },
        chunkFileNames: 'assets/[name].js',
        assetFileNames: 'assets/[name].[ext]',
        // Use ES modules for both browsers, but handle Chrome CSP
        format: 'es'
      },
      // Only make webextension-polyfill external for options, not background
      external: (id, importer) => {
        // For options script, make webextension-polyfill external (uses global)
        if (id === 'webextension-polyfill' && importer?.includes('options.ts')) {
          return true;
        }
        return false;
      }
    },
    outDir,
    emptyOutDir: true,
    target: 'es2020'
  },
  define: {
    __BUILD_TARGET__: JSON.stringify(buildTarget)
  },
  server: { port: 5173 }
});
