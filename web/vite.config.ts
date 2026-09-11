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
        manualChunks: {
          graph: ['cytoscape', 'cytoscape-fcose', 'cytoscape-dagre'],
          react: ['react', 'react-dom', 'react-router-dom', '@tanstack/react-query', 'zustand'],
          markdown: ['react-markdown'],
        },
      },
    },
  },
})
