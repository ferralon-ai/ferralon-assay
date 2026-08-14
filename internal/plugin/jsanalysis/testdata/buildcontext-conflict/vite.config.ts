import { defineConfig } from 'vite';

// C5 conflict fixture (see webpack.config.js): aliases '@app' to a DIFFERENT target than
// webpack does. Both bindings must be retained and the conflict declared.
export default defineConfig({
  resolve: {
    alias: {
      '@app': './src/app-server',
    },
  },
});
