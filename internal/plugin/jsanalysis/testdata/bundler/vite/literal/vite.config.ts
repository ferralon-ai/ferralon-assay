import { defineConfig } from 'vite';

export default defineConfig({
  resolve: {
    alias: {
      '@': './src',
      '@components': './src/components',
    },
  },
  define: {
    __APP_VERSION__: '"1.0.0"',
    __FEATURE__: true,
  },
  build: {
    rollupOptions: {
      input: './index.html',
    },
  },
});
