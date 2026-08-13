const CopyWebpackPlugin = require('copy-webpack-plugin');
const path = require('path');

module.exports = {
  /**
   * This is the main entry point for your application, it's the first file
   * that runs in the main process.
   */
  entry: './src/main.js',
  // Put your normal webpack config below here
  module: {
    rules: require('./webpack.rules'),
  },
  plugins: [
    // Copy the OpenSSH keystroke decoder worker to the webpack output so
    // the main process can spawn it via worker_threads. The worker is a
    // standalone Node script (not bundled) so it can require the decoder
    // module directly from `.webpack/main/ui/decoders/ssh-keystrokes/`.
    new CopyWebpackPlugin({
      patterns: [
        {
          from: path.join(__dirname, 'src', 'ui', 'decoders', 'ssh-keystrokes', 'worker.js'),
          to: path.join(__dirname, '.webpack', 'main', 'ui', 'decoders', 'ssh-keystrokes', 'worker.js'),
          noErrorOnMissing: false,
        },
      ],
    }),
  ],
};
