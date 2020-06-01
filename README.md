# FIDO2 -- What can a man in the browser do?
Analysis of the strength of a man in the browser against the FIDO2 authentication mechanism.

_Yet another school project_

## Abstract
This paper examines what harm a malicious browser extension can do to a FIDO2 authentication.
Many investigations on the security of FIDO2 have been published but none of them scrutinizes
browser extensions explicitly. However, browser extensions are fairly common and extremely
powerful. Therefore, this study analyzes the threat of a malicious browser extension in theory
and fortifies the findings with a practical proof of concept implementation. It identifies a rogue
browser extension as a serious threat to the level of assurance of FIDO2 as the man-in-the-browser
is able to register a forged public key and subsequently authenticate without user interaction at
any time. Hence, the suitability of FIDO2, without an additional out of band verification, as
authentication method in a high security context is questioned.

[Read more](https://github.com/cyrillbolliger/fido2/blob/master/docs/report.pdf)

## How to run the browser extension
- Install [Firefox](https://www.mozilla.org/en-US/firefox/download/), [node 12](https://nodejs.org/en/download/), [webpack 5](https://webpack.js.org/guides/installation/#local-installation) and [web-ext 4](https://extensionworkshop.com/documentation/develop/getting-started-with-web-ext/#installation-section).
- Clone the repo.
- Run `npm run build` to package the source.
- Then execute `web-ext run` to lauch Firefox with the extension.
- Navigate into the extensions console (!= the regular dev tools console).
- Register with your FIDO2 device on [webauthn.io](https://webauthn.io) (attestation type _none_), then login.
- Check the extension console to see what happend.
