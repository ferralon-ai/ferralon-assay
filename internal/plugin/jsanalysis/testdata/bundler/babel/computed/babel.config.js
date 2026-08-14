module.exports = {
  targets: { node: 'current' },
  plugins: [
    ['module-resolver', {
      alias: {
        '@root': require('path').resolve(__dirname, 'src'),
      },
    }],
    ['transform-define', {
      __ENV__: process.env.NODE_ENV,
    }],
  ],
};
