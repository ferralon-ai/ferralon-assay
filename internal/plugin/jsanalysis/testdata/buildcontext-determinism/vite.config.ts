import { defineConfig } from 'vite';

// C6 determinism fixture — vite half. Exercises: a second tool's alias map, a multi-key
// define map, and an ssr config marking the root server-side.
export default defineConfig({
  resolve: {
    alias: {
      '@ui': './src/ui',
    },
  },
  define: {
    __DEV__: 'false',
    __API__: 'https://api.example.com',
    __BUILD_ID__: '9f3c1a',
  },
  ssr: {
    target: 'node',
  },
});
