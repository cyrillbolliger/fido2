"use strict";

var cbor = require("cbor");
var base64url = require("base64url");

// main COSE labels
// defined here: https://tools.ietf.org/html/rfc8152#section-7.1
const coseLabels = {
    "kty": {
        name: 1,
        values: {
            "EC": 2,
            "RSA": 3
        }
    },
    "kid": {
        name: 2,
        values: {}
    },
    "alg": {
        name: 3,
        values: {
            "ECDSA_w_SHA256": -7,
            "EdDSA": -8,
            "ECDSA_w_SHA384": -35,
            "ECDSA_w_SHA512": -36,
            "RSASSA-PKCS1-v1_5_w_SHA256": -257,
            "RSASSA-PKCS1-v1_5_w_SHA384": -258,
            "RSASSA-PKCS1-v1_5_w_SHA512": -259,
            "RSASSA-PKCS1-v1_5_w_SHA1": -65535
        }
    },
    "key_ops": {
        name: 4,
        values: {}
    },
    "base_iv": {
        name: 5,
        values: {}
    }
};

// key-specific parameters
const keyParamList = {
    // ECDSA key parameters
    // defined here: https://tools.ietf.org/html/rfc8152#section-13.1.1
    "EC": {
        "crv": {
            name: -1,
            values: {
                "P-256": 1,
                "P-384": 2,
                "P-521": 3,
                "X25519": 4,
                "X448": 5,
                "Ed25519": 6,
                "Ed448": 7
            }
        },
        "x": {
            name: -2
            // value = Buffer
        },
        "y": {
            name: -3
            // value = Buffer
        },
        "d": {
            name: -4
            // value = Buffer
        }
    },
    // RSA key parameters
    // defined here: https://tools.ietf.org/html/rfc8230#section-4
    "RSA": {
        "n": {
            name: -1
            // value = Buffer
        },
        "e": {
            name: -2
            // value = Buffer
        },
        "d": {
            name: -3
            // value = Buffer
        },
        "p": {
            name: -4
            // value = Buffer
        },
        "q": {
            name: -5
            // value = Buffer
        },
        "dP": {
            name: -6
            // value = Buffer
        },
        "dQ": {
            name: -7
            // value = Buffer
        },
        "qInv": {
            name: -8
            // value = Buffer
        },
        "other": {
            name: -9
            // value = Array
        },
        "r_i": {
            name: -10
            // value = Buffer
        },
        "d_i": {
            name: -11
            // value = Buffer
        },
        "t_i": {
            name: -12
            // value = Buffer
        }
    }

};

function jwkToCose(jwk) {
    const retMap = new Map();
    const extraMap = new Map();

    // parse main COSE labels
    for (let [key, value] of Object.entries(jwk)) {
        if (!coseLabels[key]) {
            extraMap.set(key, value);
            continue;
        }

        let name = parseInt(coseLabels[key].name);

        if (coseLabels[key].values[value]) {
            value = coseLabels[key].values[value];

            retMap.set(name, value);
        }
    }

    const keyParams = keyParamList[jwk.kty];

    // parse key-specific parameters
    for (let [key, value] of extraMap) {
        let name = parseInt(keyParams[key].name);

        if (keyParams[key].values) {
            value = keyParams[key].values[value];
        } else {
            value = base64url.toBuffer(value);
        }

        retMap.set(name, value);
    }

    return cbor.encode(retMap);
}

module.exports = jwkToCose;
