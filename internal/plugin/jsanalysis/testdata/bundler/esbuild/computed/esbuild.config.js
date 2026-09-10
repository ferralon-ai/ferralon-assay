const { computeAlias } = require('./helpers');

require('esbuild').build({
  entryPoints: ['./src/index.ts'],
  platform: 'node',
  bundle: true,
  alias: {
    '@app': computeAlias('app'),
  },
});
