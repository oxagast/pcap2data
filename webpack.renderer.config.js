const rules = require('./webpack.rules');
const plugins = require('./webpack.plugins');
const webpack = require('webpack');

rules.push({
  test: /\.css$/,
  use: [{ loader: 'style-loader' }, { loader: 'css-loader' }],
});

module.exports = {
  // Put your normal webpack config below here
  module: {
    rules,
  },
  resolve: {
    fallback: {
      buffer: require.resolve('buffer/'),
      process: require.resolve('process/browser'),
      stream: require.resolve('stream-browserify'),
      vm: require.resolve('vm-browserify'),
    },
  },
  plugins: [
    ...plugins,
    new webpack.BannerPlugin({
      raw: true,
      entryOnly: true,
      banner: [
        'if (typeof globalThis.__dirname === "undefined") { globalThis.__dirname = "/"; }',
        'if (typeof globalThis.__filename === "undefined") { globalThis.__filename = "/index.js"; }',
        'var __dirname = globalThis.__dirname;',
        'var __filename = globalThis.__filename;',
      ].join('\n'),
    }),
    new webpack.DefinePlugin({
      __dirname: JSON.stringify('/'),
      __filename: JSON.stringify('/index.js'),
    }),
    new webpack.ProvidePlugin({
      Buffer: ['buffer', 'Buffer'],
      process: 'process/browser',
    }),
  ],
};
