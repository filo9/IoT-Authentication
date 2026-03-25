import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue()],
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html')
      }
    }
  },
  server: {
    proxy: {
      // 拦截所有 /api 开头的请求，转发给 C++ 服务器
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true
      },
      // 拦截 WebSocket 请求
      '/ws': {
        target: 'ws://127.0.0.1:8080',
        ws: true
      }
    }
  }
})