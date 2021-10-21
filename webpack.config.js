const nodeExternals = require('webpack-node-externals');
const TerserPlugin = require('terser-webpack-plugin');
const path = require('path');
module.exports = {
    entry: path.join(path.resolve(__dirname, 'js-output'), 'index.js'),
    output: {
        filename: 'ic-stoic-identity.js',
        library: 'ic-stoic-identity',
        libraryTarget: 'umd',
        umdNamedDefine: true,
        globalObject: 'this',
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
