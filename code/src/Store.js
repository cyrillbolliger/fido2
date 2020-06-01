export default class Store {
    static async get(key) {
        const promise = browser.storage.local.get(key);

        return promise.then(obj => obj[key]);
    }

    static async put(key, value){
        return browser.storage.local.set({[key]: value});
    }
}