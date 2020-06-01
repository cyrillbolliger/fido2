import base64url from "base64url";

export default class MyAuthenticatorResponse {
    /**
     * Decodes and adds the clientDataJSON
     *
     * @param {string} base64
     * @protected
     */
    addClientDataJson(base64) {
        const string = base64url.decode(base64);
        this.clientDataJSON = JSON.parse(string);
    }

    encodeClientDataJson() {
        const string = JSON.stringify(this.clientDataJSON);
        return base64url.encode(string);
    }
}