const Type = {
    unknown: 'Unknown',
    publicKeyCredentialCreationOptions: 'PublicKeyCredentialCreationOptions',
    publicKeyCredential: 'PublicKeyCredential',
    publicKeyCredentialRequestOptions: 'PublicKeyCredentialRequestOptions'
};

const CandidateMatchers = {
    [Type.publicKeyCredentialCreationOptions]: RegExp('(?=[^]*?publicKey)(?=[^]*?challenge)(?=[^]*?pubKeyCredParams)'),
    [Type.publicKeyCredential]: RegExp('(?=[^]*?rawId)(?=[^]*?clientDataJSON)'),
    [Type.publicKeyCredentialRequestOptions]: RegExp('(?=[^]*?publicKey)(?=[^]*?challenge)(?![^]*?pubKeyCredParams)')
};

const TypeProperties = {
    [Type.publicKeyCredentialCreationOptions]: ['rp', 'user', 'challenge', 'pubKeyCredParams'],
    [Type.publicKeyCredential]: ['rawId', 'response'],
    [Type.publicKeyCredentialRequestOptions]: ['challenge']
};

class WebAuthnMatcher {
    // webAuthnData;

    constructor(body) {
        this.body = body;
    }

    analyze() {
        let type = this.isWebAuthnCandidate();
        
        if (Type.unknown !== type) {
            type = this.isWebAuthn(type);
        }
        
        return type;
    }

    isWebAuthnCandidate() {
        for (let [key, matcher] of Object.entries(CandidateMatchers)) {
            if (matcher.test(this.body)) {
                return key;
            }
        }

        return Type.unknown;
    }

    isWebAuthn(candidateType) {
        let json, data;

        // it must be valid json
        try {
            json = JSON.parse(this.body);
        } catch (SyntaxError) {
            return Type.unknown;
        }

        // the data of requests is always stored under the property 'publicKey'
        // the credential response not.
        if (Type.publicKeyCredential === candidateType) {
            data = json;
        } else {
            
            if (!json.publicKey) {
                return Type.unknown;
            }

            data = json.publicKey;
        }

        // check, that the data contains all required properties
        for (let propertyName of TypeProperties[candidateType]) {
            if (!data[propertyName]) {
                return Type.unknown;
            }
        }

        this.webAuthnData = json;
        return candidateType;
    }
}

export {
    WebAuthnMatcher,
    Type
}