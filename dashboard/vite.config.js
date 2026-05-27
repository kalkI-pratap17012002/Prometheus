import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dashboard talks to the ml_engine FastAPI service. In docker-compose we
// run on a shared network so http://ml_engine:8000 resolves; in local `npm
// run dev` we hit the host-side localhost forward on :8000.
const API_TARGET = process.env.VITE_API_TARGET || 'http://localhost:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    strictPort: true,
    proxy: {
      '/api':       { target: API_TARGET, changeOrigin: true },
      '/ip-rules':  { target: API_TARGET, changeOrigin: true },
      '/ip-check':  { target: API_TARGET, changeOrigin: true },
      '/ws':        { target: API_TARGET.replace(/^http/, 'ws'), ws: true },
    },
  },
  preview: {
    host: '0.0.0.0',
    port: 3000,
  },
})
