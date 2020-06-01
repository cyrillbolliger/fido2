function arrayBufferToString(blobs) {
    const decoder = new TextDecoder();
    let content = '';

    for (let buffer of blobs) {
        content += decoder.decode(buffer, {stream: true});
    }
    content += decoder.decode();

    return content;
}

function stringToArrayBuffer(string) {
    const encoder = new TextEncoder();
    const uint8arr = encoder.encode(string);

    return new Uint8Array(uint8arr).buffer;
}

function arrayBufferToHex(buffer) {
    // https://stackoverflow.com/a/40031979
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

function arrayBufferToByteArray(buffer) {
    return new Uint8Array(buffer);
}

export {
    arrayBufferToString,
    stringToArrayBuffer,
    arrayBufferToHex,
    arrayBufferToByteArray
}