import alias from '@rollup/plugin-alias';
import replace from '@rollup/plugin-replace';

export default {
  input: './src/main.js',
  output: {
    dir: 'dist',
    format: 'esm',
  },
  plugins: [
    alias({
      entries: {
        '@lib': './src/lib',
        '@utils': './src/utils',
      },
    }),
    replace({
      values: {
        __VERSION__: '"2.0.0"',
      },
    }),
  ],
};
