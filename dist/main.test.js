"use strict";
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = __importStar(require("./main"));
const value = 'hello subspace';
const falseValue = 'herro rubrace';
const hash = '00ba5188adff22ee1f8abc61d6e96c371f0d505ec76f90e86d4b0c8748d646bb';
const generateKeys = async () => {
    const options = {
        userIds: [{
                name: 'me',
                email: 'me@me.com'
            }],
        curve: "ed25519",
        passphrase: 'some text'
    };
    const key = await crypto.generateKeys(options);
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
test('stringify', () => {
    const stringInput = 'test';
    const stringOutput = 'test';
    expect(crypto.stringify(stringInput)).toBe(stringOutput);
    const arrayInput = [1, 'abc', 'signature'];
    const arrayOutput = "1,abc,signature";
    expect(crypto.stringify(arrayInput)).toBe(arrayOutput);
    const objectInput = {
        test: 'data',
        some: [1, 2, 3]
    };
    const objectOutput = '{"test":"data","some":[1, 2, 3]}';
    expect(crypto.stringify(arrayInput)).toBe(arrayOutput);
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
// test('generateKeys',() => {
// })
//# sourceMappingURL=main.test.js.map