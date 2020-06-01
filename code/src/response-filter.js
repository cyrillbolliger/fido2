import {arrayBufferToString} from './util';

export default class ResponseFilter {
    static getBody(response) {
        const filter = browser.webRequest.filterResponseData(response.requestId);

        let resolve;
        const typePromise = new Promise(res => resolve = res);

        let blobs = [];

        filter.ondata = event => {
            blobs.push(event.data);

            // we don't change the response, so it can be forwarded immediately
            filter.write(event.data);
        };

        filter.onstop = () => {
            filter.close();

            resolve(arrayBufferToString(blobs));
        };

        return typePromise;
    }
}