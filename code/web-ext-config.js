module.exports = {
    verbose: false,
    build: {overwriteDest: true},
    run: {
        startUrl: [
            "https://webauthn.io",
            "about:debugging#/runtime/this-firefox"
        ],
        watchFile: "dist/bundle.js"
    }
};