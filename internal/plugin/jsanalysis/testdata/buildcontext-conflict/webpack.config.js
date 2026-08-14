// C5 conflict fixture: this webpack config aliases '@app' to a browser build, while the
// sibling vite.config.ts aliases the SAME key to a server build. The two configs disagree
// and the build context must DECLARE the conflict (never pick a silent winner). '@shared'
// is declared only here, so it must NOT be flagged as a conflict.
module.exports = {
  resolve: {
    alias: {
      '@app': './src/app-web',
      '@shared': './src/shared',
    },
  },
};
