// C6 determinism fixture — webpack half. Exercises: JS-dialect alias map (source order),
// a node target (server-side root), an entry point, and a multi-key DefinePlugin (a
// several-key literal object, to catch any map-order leak into the encoding).
const webpack = require('webpack');

module.exports = {
  target: 'node',
  entry: './src/server.js',
  resolve: {
    alias: {
      '@app': './src/app',
      '@shared': './src/shared',
      '@config': './src/config',
    },
  },
  plugins: [
    new webpack.DefinePlugin({
      'process.env.NODE_ENV': 'production',
      '__VERSION__': '1.2.3',
      '__REGION__': 'us-east-1',
    }),
  ],
};
