import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { createReadStream, existsSync, statSync } from 'node:fs'
import type { IncomingMessage, ServerResponse } from 'node:http'
import path from 'node:path'
import { defineConfig, type Plugin } from 'vite'

// `VITE_STATIC=1 npm run build` produces the static snapshot edition (docs/10-static-snapshot.md): relative asset
// URLs so the site can live under a sub-path or an artifact origin, a separate outDir, hash routing (App.tsx) and the
// snapshot transport (src/api/snapshot). Vite exposes VITE_* variables to the client automatically.
const isStatic = process.env.VITE_STATIC === '1'

/** Dev/preview servers only: serve `web/snapshot-out/` at `/snapshot/` so `?snapshot=1` can be tried without copying files. */
function serveSnapshotOut(): Plugin {
  const dir = path.resolve(import.meta.dirname, 'snapshot-out')
  const handler = (req: IncomingMessage, res: ServerResponse, next: () => void) => {
    const url = req.url ?? ''
    if (!url.startsWith('/snapshot/')) return next()
    const rel = decodeURIComponent(url.slice('/snapshot/'.length).split('?')[0])
    const file = path.resolve(dir, rel)
    if (!file.startsWith(dir + path.sep) || !existsSync(file) || !statSync(file).isFile()) {
      res.statusCode = 404
      res.end(`not found: ${rel} (run web/scripts/make-fixture-snapshot.mjs or scripts/export_snapshot.py first)`)
      return
    }
    res.setHeader('content-type', file.endsWith('.json') ? 'application/json' : 'application/octet-stream')
    createReadStream(file).pipe(res)
  }
  return {
    name: 'throughline:serve-snapshot-out',
    configureServer(server) {
      server.middlewares.use(handler)
    },
    configurePreviewServer(server) {
      server.middlewares.use(handler)
    },
  }
}

/** Static builds only: the artifact publisher rejects files that contain a literal U+FFFD (micromark emits one inside a
 * template literal), so emit it as the equivalent escape sequence instead. */
function escapeReplacementChar(): Plugin {
  return {
    name: 'throughline:escape-u-fffd',
    apply: 'build',
    // generateBundle runs after minification (a renderChunk rewrite would be folded back into the literal character).
    generateBundle(_options, bundle) {
      for (const item of Object.values(bundle)) {
        if (item.type === 'chunk' && item.code.includes('\uFFFD')) item.code = item.code.replaceAll('\uFFFD', '\\uFFFD')
      }
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  base: isStatic ? './' : '/',
  plugins: [react(), tailwindcss(), serveSnapshotOut(), ...(isStatic ? [escapeReplacementChar()] : [])],
  server: {
    port: 5173,
    proxy: {
      // FastAPI backend (see docs/05-api-contract.md); the mock adapter takes over when this is unreachable in dev.
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: true },
    },
  },
  preview: { port: 4173 },
  build: {
    outDir: isStatic ? 'dist-static' : 'dist',
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
