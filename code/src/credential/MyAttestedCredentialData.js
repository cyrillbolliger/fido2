import coseToJwt from 'cose-to-jwk';
import jwtToCose from '../util/jwk-to-cose';

const AAGUID_LEN = 16;
const CRED_ID_LEN_LEN = 2;
const CRED_ID_START = AAGUID_LEN + CRED_ID_LEN_LEN;

export default class MyAttestedCredentialData {

    /**
     * Returns a MyAttestedCredentialData object from the given byte array
     *
     * @param {Uint8Array} byteArray
     * @returns {MyAttestedCredentialData}
     */
    static decode(byteArray) {
        const data = new MyAttestedCredentialData();

        data.aaguid = byteArray.slice(0, AAGUID_LEN);
        data.credentialIdLength = this._getCredentialIdLength(byteArray.slice(AAGUID_LEN, CRED_ID_START));
        data.credentialId = byteArray.slice(CRED_ID_START, CRED_ID_START + data.credentialIdLength);
        data.credentialPublicKey = this._getPublicKeyObject(byteArray.slice(CRED_ID_START + data.credentialIdLength));

        return data;
    }

    encode() {
        const pubKey = this._encodePublicKeyObject();
        const len = AAGUID_LEN + CRED_ID_LEN_LEN + this.credentialIdLength + pubKey.byteLength;
        const buffer = new Uint8Array(len);

        buffer.set(this.aaguid, 0);
        buffer.set(this._encodeCredentialIdLength(), AAGUID_LEN);
        buffer.set(this.credentialId, CRED_ID_START);
        buffer.set(pubKey, CRED_ID_START + this.credentialIdLength);

        return buffer;
    }

    /**
     * Set a new public key
     *
     * @param {CryptoKeyPair} keyPair
     */
    async setKey(keyPair) {
        this.credentialPublicKey = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

        // not implemented in jwkToCose
        delete this.credentialPublicKey.key_ops;

        // non standard field
        // https://tools.ietf.org/html/rfc7517#section-4
        delete this.credentialPublicKey.ext;

        // todo: respect the parameters that the rp has sent
        // now this only works, because the key parameters are hardcoded
        this.credentialPublicKey.alg = 'ECDSA_w_SHA256';
    }

    /**
     * Converts the given (big endian) byteArray into a number
     *
     * @param {Uint8Array} byteArray
     * @returns {number}
     * @private
     */
    static _getCredentialIdLength(byteArray) {
        const dataView = new DataView(new ArrayBuffer(2));
        byteArray.forEach((value, index) => dataView.setUint8(index, value));
        return dataView.getUint16(0, false);
    }

    _encodeCredentialIdLength() {
        const buffer = new Uint8Array(2);
        let len = parseInt(this.credentialIdLength);
        let lower, upper;

        lower = len & 0x00ff;
        upper = len >>> 8;

        buffer[0] = upper;
        buffer[1] = lower;

        return buffer;
    }

    /**
     * Decodes the given byteArray into a JSON Web Key
     *
     * @param {Uint8Array} byteArray
     * @returns {Map}
     * @private
     */
    static _getPublicKeyObject(byteArray) {
        return coseToJwt(byteArray);
    }

    _encodePublicKeyObject() {
        return jwtToCose(this.credentialPublicKey);
    }
}