import MyAuthenticatorResponse from "./MyAuthenticatorResponse";
import MyAttestationObject from "./MyAttestationObject";

export default class MyAuthenticatorAttestationResponse extends MyAuthenticatorResponse {
    /**
     * Returns a MyAuthenticatorAttestationResponse from the given object.
     *
     * @param {object} obj
     * @returns {MyAuthenticatorAttestationResponse}
     */
    static decode(obj) {
        const response = new MyAuthenticatorAttestationResponse();

        response.addClientDataJson(obj.clientDataJSON);
        response.attestationObject = MyAttestationObject.decode(obj.attestationObject);

        return response;
    }

    /**
     * Set a new public key
     *
     * @param {CryptoKeyPair} keyPair
     */
    async setKey(keyPair) {
        await this.attestationObject.setKey(keyPair);
    }

    /**
     * Inverse the decode method
     *
     * @returns {Object}
     */
    encode() {
        const obj = {};

        obj.attestationObject = this.attestationObject.encode();
        obj.clientDataJSON = this.encodeClientDataJson();

        return obj;
    }
}