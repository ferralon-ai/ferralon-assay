const webpack = require('webpack');

module.exports = {
  target: 'node',
  entry: {
    app: './src/app.js',
    admin: './src/admin.js',
  },
  resolve: {
    alias: {
      '@components': './src/components',
      utils: './src/utils',
    },
  },
  plugins: [
    new webpack.DefinePlugin({
      __DEV__: 'false',
      VERSION: '"1.2.3"',
    }),
  ],
};
