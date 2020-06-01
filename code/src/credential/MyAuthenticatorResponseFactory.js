import MyAuthenticatorAttestationResponse from "./MyAuthenticatorAttestationResponse";
import MyAuthenticatorAssertionResponse from "./MyAuthenticatorAssertionResponse";

export default class MyAuthenticatorResponseFactory {
    /**
     * Returns a MyAuthenticatorAttestationResponse or a
     * MyAuthenticatorAssertionResponse from the given object.
     *
     * @param {object} obj
     * @returns {MyAuthenticatorAttestationResponse|MyAuthenticatorAssertionResponse}
     */
    static build(obj) {
        if (!'clientDataJSON' in obj) {
            throw 'Invalid authenticator response data';
        }

        if ('attestationObject' in obj) {
            return MyAuthenticatorAttestationResponse.decode(obj);
        }

        if ('signature' in obj && 'authenticatorData' in obj) {
            return MyAuthenticatorAssertionResponse.decode(obj);
        }

        throw 'Invalid authenticator response data';
    }
}