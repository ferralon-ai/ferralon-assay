const computeVersion = require('./version');

module.exports = {
  jsc: {
    paths: {
      '@app/*': ['./src/app/*'],
    },
    transform: {
      optimizer: {
        globals: {
          vars: {
            VERSION: computeVersion(),
          },
        },
      },
    },
  },
};
