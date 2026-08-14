const webpack = require('webpack');
const path = require('path');

module.exports = {
  target: 'node',
  entry: './src/index.js',
  resolve: {
    alias: {
      '@components': path.resolve(__dirname, 'src/components'),
    },
  },
};
