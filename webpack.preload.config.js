module.exports = {
  // ...existing config
  target: 'electron-preload',
  externals: {
    child_process: 'commonjs2 child_process',
    fs: 'commonjs2 fs',
    net: 'commonjs2 net',
    os: 'commonjs2 os',
    path: 'commonjs2 path',
    vm: 'commonjs2 vm',
  },
};
