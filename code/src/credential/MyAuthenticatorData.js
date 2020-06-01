import MyAttestedCredentialData from "./MyAttestedCredentialData";

export default class MyAuthenticatorData {
    /**
     * Returns a MyAuthenticatorData object from the given byte Array
     *
     * @param {Uint8Array} byteArray
     * @returns {MyAuthenticatorData}
     */
    static decode(byteArray) {
        const data = new MyAuthenticatorData();

        data.rpIdHash = byteArray.slice(0, 32);
        data.flags = this._decodeFlags(byteArray.slice(32, 33)[0]);
        data.signCount = this._decodeSignCount(byteArray.slice(33, 37));
        data._rawSigCount = byteArray.slice(33, 37);

        if (byteArray.byteLength > 37) {
            // todo: handle properly if there are extensions (extensions come after the public key, so we must cap the slice).
            data.attestedCredentialData = MyAttestedCredentialData.decode(byteArray.slice(37));
        }

        return data;
    }

    encode() {
        let attestedCredentialDataLength = 0;

        if (this.attestedCredentialData) {
            const attested = this.attestedCredentialData.encode();
            attestedCredentialDataLength = attested.byteLength;
        }

        const buffer = new Uint8Array(37 + attestedCredentialDataLength);

        buffer.set(this.rpIdHash, 0);
        buffer.set(this._encodeFlags(), 32);
        buffer.set(this._rawSigCount, 33);

        if (this.attestedCredentialData){
            buffer.set(this.attestedCredentialData.encode(), 37);
        }

        return buffer;
    }

    /**
     * Set a new public key
     *
     * @param {CryptoKeyPair} keyPair
     */
    async setKey(keyPair) {
        await this.attestedCredentialData.setKey(keyPair);
    }

    /**
     * Returns a Set of all flags that are set
     *
     * @param {UInt8} byte
     * @returns {Set<unknown>}
     * @private
     */
    static _decodeFlags(byte) {
        const flagsSet = new Set();

        if (byte & 0x01) flagsSet.add("UP");
        if (byte & 0x02) flagsSet.add("RFU1");
        if (byte & 0x04) flagsSet.add("UV");
        if (byte & 0x08) flagsSet.add("RFU3");
        if (byte & 0x10) flagsSet.add("RFU4");
        if (byte & 0x20) flagsSet.add("RFU5");
        if (byte & 0x40) flagsSet.add("AT");
        if (byte & 0x80) flagsSet.add("ED");

        return flagsSet;
    }

    /**
     * Converts the flags into a byte
     *
     * @returns {Array}
     */
    _encodeFlags() {
        let byte = 0;

        if (this.flags.has("UP")) byte += 0x01;
        if (this.flags.has("RFU1")) byte += 0x02;
        if (this.flags.has("UV")) byte += 0x04;
        if (this.flags.has("RFU3")) byte += 0x08;
        if (this.flags.has("RFU4")) byte += 0x10;
        if (this.flags.has("RFU5")) byte += 0x20;
        if (this.flags.has("AT")) byte += 0x40;
        if (this.flags.has("ED")) byte += 0x80;

        return [byte];
    }

    /**
     * Converts the given (big endian) byteArray into a number
     *
     * @param {Uint8Array} byteArray
     * @returns {number}
     * @private
     */
    static _decodeSignCount(byteArray) {
        const dataView = new DataView(new ArrayBuffer(4));
        byteArray.forEach((value, index) => dataView.setUint8(index, value));
        return dataView.getUint32(0, false);
    }
}