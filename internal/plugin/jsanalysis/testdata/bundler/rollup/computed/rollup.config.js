import alias from '@rollup/plugin-alias';

export default {
  input: process.env.ENTRY,
  plugins: [
    alias({
      entries: {
        '@lib': resolvePath('./src/lib'),
      },
    }),
  ],
};
