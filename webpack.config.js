const nodeExternals = require('webpack-node-externals');
const TerserPlugin = require("terser-webpack-plugin");
module.exports = {
  output: {
    filename: 'ic-stoic-identity.js',
    library: 'ic-stoic-identity',
    libraryTarget:'umd',
    umdNamedDefine: true ,
    globalObject: 'this'
  },
  externals: [nodeExternals()],
  optimization: {
    minimize: true,
    minimizer: [
      new TerserPlugin({
        terserOptions: {
          keep_classnames: true,
          keep_fnames: true,
        },
      }),
    ],
  },
};