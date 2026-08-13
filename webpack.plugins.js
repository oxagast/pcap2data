const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');

class FixForgeRendererPathsPlugin {
  apply(compiler) {
    compiler.hooks.compilation.tap('FixForgeRendererPathsPlugin', (compilation) => {
      const { Compilation, sources } = compiler.webpack;
      compilation.hooks.processAssets.tap(
        {
          name: 'FixForgeRendererPathsPlugin',
          stage: Compilation.PROCESS_ASSETS_STAGE_OPTIMIZE_INLINE,
        },
        () => {
          const htmlAssetName = 'main_window/index.html';
          const htmlAsset = compilation.getAsset(htmlAssetName);
          if (!htmlAsset) {
            return;
          }

          let html = htmlAsset.source.source().toString();
          html = html.replace(/src="\/main_window\//g, 'src="../main_window/');
          html = html.replace(/href="assets\/css\/style\.css"/g, 'href="../assets/css/style.css"');
          // Vendored Plotly script is referenced relative to the asar root,
          // so we need the same ../assets/ prefix the css fix-up uses.
          html = html.replace(
            /src="assets\/vendor\/plotly-2\.35\.2\.min\.js"/,
            'src="../assets/vendor/plotly-2.35.2.min.js"',
          );

          compilation.updateAsset(htmlAssetName, new sources.RawSource(html));
        },
      );
    });
  }
}

module.exports = [
  new CopyPlugin({
    patterns: [
      {
        from: path.resolve(__dirname, 'src/assets'),
        to: 'assets',
      },
      {
        from: path.resolve(__dirname, 'src/data'),
        to: 'data',
      },
    ],
  }),
  new FixForgeRendererPathsPlugin(),
];
