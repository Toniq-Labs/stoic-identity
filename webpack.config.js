const TerserPlugin = require("terser-webpack-plugin");
module.exports = {
  output: {
    filename: 'identity-stoic.js'
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