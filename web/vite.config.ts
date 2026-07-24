import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Built output is embedded into the Go binary via embed.FS.
  build: { outDir: '../internal/web/dist', emptyOutDir: true },
  server: {
    port: 5173,
    proxy: { '/api': { target: 'https://127.0.0.1:8443', changeOrigin: true, secure: false } },
  },
})
