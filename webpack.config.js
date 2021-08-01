const TerserPlugin = require("terser-webpack-plugin");
module.exports = {
  output: {
    filename: 'ic-stoic-identity.js',
    library: 'ic-stoic-identity',
    libraryTarget:'umd',
    umdNamedDefine: true 
  },
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