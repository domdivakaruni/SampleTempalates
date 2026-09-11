import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  base: '/',
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      // FastAPI backend (see docs/05-api-contract.md); the mock adapter takes over when this is unreachable in dev.
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true },
    },
  },
  preview: { port: 4173 },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        // Function form: the object form is not accepted by Rollup's typings in Vite 8.
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return undefined
          if (/[\\/](cytoscape|cytoscape-fcose|cytoscape-dagre|cose-base|layout-base|dagre|@dagrejs)[\\/]/.test(id)) return 'graph'
          if (/[\\/](react-markdown|remark-|mdast-|micromark|unified|unist-|hast-|vfile|property-information|html-url-attributes|comma-separated-tokens|space-separated-tokens|decode-named-character-reference|character-entities|trim-lines|devlop|bail|is-plain-obj|trough|zwitch|estree-util|style-to-js|style-to-object|inline-style-parser|extend|ccount|escape-string-regexp|markdown-table|longest-streak)/.test(id)) return 'markdown'
          if (/[\\/](react|react-dom|react-router|react-router-dom|@tanstack|zustand|scheduler|@remix-run|cookie|set-cookie-parser|turbo-stream|use-sync-external-store)[\\/]/.test(id)) return 'react'
          return undefined
        },
      },
    },
  },
})
