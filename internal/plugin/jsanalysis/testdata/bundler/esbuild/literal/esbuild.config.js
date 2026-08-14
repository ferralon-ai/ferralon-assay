require('esbuild').build({
  entryPoints: ['./src/index.ts', './src/worker.ts'],
  platform: 'node',
  bundle: true,
  alias: {
    '@app': './src/app',
  },
  define: {
    'process.env.NODE_ENV': '"production"',
    DEBUG: 'false',
  },
});
