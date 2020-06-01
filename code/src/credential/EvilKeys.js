import Store from "../Store";
import {arrayBufferToString} from "../util";

const EVIL_KEY_ALGO = {name: "ECDSA", namedCurve: "P-256", hash: "SHA-256"};

/**
 * @class
 * @implements {CryptoKeyPair}
 */
export default class EvilKeys {
    constructor(keyId) {
        this.keyId = keyId;
    }

    /**
     * Generates a new key pair for this credential
     */
    async generate() {
        const evilKeys = await crypto.subtle.generateKey(
            this.getAlgos(),
            true,
            ["sign", "verify"]
        );

        this.privateKey = evilKeys.privateKey;
        this.publicKey = evilKeys.publicKey;
    }

    /**
     * Saves the new key pair in web storage of the extension
     */
    async save() {
        const privateKey = await crypto.subtle.exportKey('jwk', this.privateKey);
        const publicKey = await crypto.subtle.exportKey('jwk', this.publicKey);

        await Store.put(this.keyId, {privateKey, publicKey});
    }

    /**
     * Loads the key pair from the web storage of the extension
     */
    async load() {
        const keys = await Store.get(this.keyId);
        this.privateKey = await crypto.subtle.importKey(
            'jwk',
            keys.privateKey,
            this.getAlgos(),
            true,
            ["sign"]
        );
        this.publicKey = await crypto.subtle.importKey(
            'jwk',
            keys.publicKey,
            this.getAlgos(),
            true,
            ["verify"]
        );
    }

    async getPubKeyPem() {
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";

        return await crypto.subtle.exportKey('spki', this.publicKey)
            .then(arrayBuffer => String.fromCharCode(...new Uint8Array(arrayBuffer)))
            .then( blob => window.btoa(blob))
            .then(base64 => `${pemHeader} ${base64} ${pemFooter}`)
    }

    getAlgos() {
        return EVIL_KEY_ALGO;
    }
}