(function (factory) {
    if (typeof module === "object" && typeof module.exports === "object") {
        var v = factory(require, exports);
        if (v !== undefined) module.exports = v;
    }
    else if (typeof define === "function" && define.amd) {
        define(["require", "exports", "./crypto"], factory);
    }
})(function (require, exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    const crypto = require("./crypto");
    const value = 'hello subspace';
    const falseValue = 'herro rubrace';
    const hash = '00ba5188adff22ee1f8abc61d6e96c371f0d505ec76f90e86d4b0c8748d646bb';
    const generateKeys = async () => {
        const name = 'me';
        const email = 'me@me.com';
        const passphrase = 'some text';
        const key = await crypto.generateKeys(name, email, passphrase);
        const profile = {
            publicKey: key.publicKeyArmored,
            privateKey: key.privateKeyArmored,
            privateKeyObject: await crypto.getPrivateKeyObject(key.privateKeyArmored, 'some text')
        };
        return profile;
    };
    const keys = generateKeys();
    test('getHash', () => {
        expect(crypto.getHash(value)).toBe(hash);
    });
    // test('getRandom', () => {
    //     expect(crypto.getRandom)
    //     // 32 bytes long
    //     // unique each time
    // })
    test('read', () => {
        const buffer = Buffer.from(hash, 'hex');
        const readable = '00ba5188...';
        expect(crypto.read(buffer)).toBe(readable);
    });
    test('verifyHash', () => {
        expect(crypto.isValidHash(hash, value)).toBe(true);
        expect(crypto.isValidHash(hash, falseValue)).toBe(false);
    });
    test('verifyDate', () => {
        const range = 600000;
        const testDate = Date.now();
        const validEarly = testDate - 599000;
        expect(crypto.isDateWithinRange(validEarly, range)).toBe(true);
        const validLate = testDate + 599000;
        expect(crypto.isDateWithinRange(validLate, range)).toBe(true);
        const invalidEarly = testDate - 601000;
        expect(crypto.isDateWithinRange(invalidEarly, range)).toBe(false);
        const invalidLate = testDate + 601000;
        expect(crypto.isDateWithinRange(invalidLate, range)).toBe(false);
    });
});
// test('generateKeys',() => {
// })
//# sourceMappingURL=crypto.test.js.map