import MyAuthenticatorResponse from "./MyAuthenticatorResponse";
import {stringToArrayBuffer, arrayBufferToByteArray, arrayBufferToHex} from "../util";
import MyAuthenticatorData from "./MyAuthenticatorData";
import base64url from "base64url";
import asn from "asn1.js";

export default class MyAuthenticatorAssertionResponse extends MyAuthenticatorResponse {
    /**
     * Return a MyAuthenitcatorAssertionResponse from the given object
     *
     * @param {Object} obj
     * @returns {MyAuthenticatorAssertionResponse}
     */
    static decode(obj) {
        const response = new MyAuthenticatorAssertionResponse();

        response.addClientDataJson(obj.clientDataJSON);
        response.authenticatorData = MyAuthenticatorData.decode(base64url.toBuffer(obj.authenticatorData));
        response.signature = base64url.decode(obj.signature);

        if ('userHandle' in obj) {
            response.userHandle = obj.userHandle;
        }

        return response;
    }

    encode() {
        const obj = {};

        obj.authenticatorData = base64url.encode(this.authenticatorData.encode());
        obj.clientDataJSON = this.encodeClientDataJson();
        obj.signature = base64url.encode(this.signature);

        if ('userHandle' in this) {
            obj.userHandle = this.userHandle;
        }

        return obj;
    }

    async sign(evilKeys) {
        const data = await this._getSignatureInput();
        const signature = await crypto.subtle.sign(evilKeys.getAlgos(), evilKeys.privateKey, data);
        this.signature = this.encodeSignature(signature);
    }

    async _generateClientDataHash() {
        const clientDataString = JSON.stringify(this.clientDataJSON);
        const clientDataArrayBuffer = stringToArrayBuffer(clientDataString);

        return await crypto.subtle.digest('SHA-256', clientDataArrayBuffer);
    }

    async _getSignatureInput() {
        const authenticatorData = this.authenticatorData.encode();
        const clientDataHashBuffer = await this._generateClientDataHash();
        const clientDataHash = arrayBufferToByteArray(clientDataHashBuffer);

        const buffer = new Uint8Array(authenticatorData.byteLength + clientDataHashBuffer.byteLength);
        buffer.set(authenticatorData, 0);
        buffer.set(clientDataHash, authenticatorData.byteLength);

        return buffer;
    }

    encodeSignature(signature) {
        const bytes = arrayBufferToByteArray(signature);
        const r = this._makePositiveInt(bytes.slice(0, 32));
        const s = this._makePositiveInt(bytes.slice(32));

        const Signature = asn.define('Signature', function () {
            this.seq().obj(
                this.key('r').int(),
                this.key('s').int()
            );
        });

        return Signature.encode({
            r: Buffer.from(r),
            s: Buffer.from(s)
        }, 'der');
    }


    /**
     * Ensures the first bit isn't 1. If so, a byte of 0s is prepended.
     *
     * @param {Uint8Array} bytes
     * @returns {Uint8Array}
     * @private
     */
    _makePositiveInt(bytes) {
        if (0x80 > bytes[0]) {
            return bytes;
        } else {
            let tmp = new Uint8Array(bytes.byteLength + 1);
            tmp.set([0], 0);
            tmp.set(bytes, 1);

            return tmp;
        }
    }
}