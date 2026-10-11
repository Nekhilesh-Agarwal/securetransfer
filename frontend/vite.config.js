import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

const backend = process.env.VITE_BACKEND_URL || 'http://127.0.0.1:8000'

const proxy = {
  '/auth': { target: backend, changeOrigin: true },
  '/messages': { target: backend, changeOrigin: true },
  '/sessions': { target: backend, changeOrigin: true },
  '/files': { target: backend, changeOrigin: true },
  '/voice': { target: backend, changeOrigin: true },
  '/devices': { target: backend, changeOrigin: true },
  '/audit': { target: backend, changeOrigin: true },
  '/admin': { target: backend, changeOrigin: true },
  '/security': { target: backend, changeOrigin: true },
  '/binary': { target: backend, changeOrigin: true },
  '/health': { target: backend, changeOrigin: true },
  '/device': { target: backend, changeOrigin: true },
}

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    strictPort: true,
    proxy,
  },
  preview: {
    host: true,
    port: 5173,
    proxy,
  },
})
