const path = require('path');

const outDir = path.resolve(__dirname, 'dist');

module.exports = {
    mode: 'development',
    devtool: 'inline-source-map',
    entry: './src/index.js',
    output: {
        filename: 'bundle.js',
        path: outDir,
    }
};