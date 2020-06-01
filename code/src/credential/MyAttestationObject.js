import base64url from "base64url";
import cbor from "cbor";
import MyAuthenticatorData from "./MyAuthenticatorData";

export default class MyAttestationObject {
    /**
     * Returns a MyAttestationObject from the given base64url encoded CBOR object
     *
     * @param {string} encodedObj base64url encoded CBOR object
     * @returns {MyAttestationObject}
     */
    static decode(encodedObj) {
        const attestation = new MyAttestationObject();

        const buffer = base64url.toBuffer(encodedObj);
        const obj = cbor.decodeAllSync(buffer)[0];

        if (!('authData' in obj && 'fmt' in obj && 'attStmt' in obj)) {
            throw 'Invalid attestation object data';
        }

        attestation.authData = MyAuthenticatorData.decode(obj.authData);
        attestation.fmt = obj.fmt;
        attestation.attStmt = obj.attStmt;

        return attestation;
    }

    /**
     * Set a new public key
     *
     * @param {CryptoKeyPair} keyPair
     */
    async setKey(keyPair) {
        await this.authData.setKey(keyPair);
    }

    encode() {
        const obj = {};

        obj.authData = this.authData.encode();
        obj.fmt = this.fmt;
        obj.attStmt = this.attStmt;

        const buffer = cbor.encode(obj);

        return base64url.encode(buffer);
    }
}