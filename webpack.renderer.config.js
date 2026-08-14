const rules = require('./webpack.rules');
const plugins = require('./webpack.plugins');
const webpack = require('webpack');
const path = require('path');

rules.push({
  test: /\.css$/,
  use: [{ loader: 'style-loader' }, { loader: 'css-loader' }],
});

module.exports = {
  // The renderer entry. electron-forge's webpack plugin overrides
  // this via its `entryPoints` config (see forge.config.js) and
  // generates per-HTML-window entries — when the plugin is active,
  // our `entry` is ignored in favour of forge's. When invoking this
  // config directly via `npx webpack --config webpack.renderer.config.js`
  // (e.g. for syntax checks outside electron-forge), the explicit
  // entry below lets webpack resolve a real file instead of falling
  // back to the directory `./src` (which contains index.html + assets/
  // but no `index.js`, producing "Can't resolve './src'" errors).
  entry: './src/renderer.js',
  // Output path for CLI builds. Forge supplies its own output
  // directory when invoked via electron-forge, so this default is
  // only used when running webpack directly. Mirror the conventional
  // `.webpack/renderer/` layout that the main config's bundled output
  // also lands in.
  output: {
    path: path.resolve(__dirname, '.webpack/renderer'),
    filename: 'renderer.js',
  },
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
