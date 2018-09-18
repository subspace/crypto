"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const main_1 = __importDefault(require("./main"));
const value = 'hello subspace';
const falseValue = 'herro rubrace';
const hash = '00ba5188adff22ee1f8abc61d6e96c371f0d505ec76f90e86d4b0c8748d646bb';
const generateKeys = () => __awaiter(this, void 0, void 0, function* () {
    const options = {
        userIds: [{
                name: 'me',
                email: 'me@me.com'
            }],
        curve: "ed25519",
        passphrase: 'some text'
    };
    const key = yield main_1.default.generateKeys(options);
    const profile = {
        publicKey: key.publicKeyArmored,
        privateKey: key.privateKeyArmored,
        privateKeyObject: yield main_1.default.getPrivateKeyObject(key.privateKeyArmored)
    };
    return profile;
});
const keys = generateKeys();
test('getHash', () => {
    expect(main_1.default.getHash(value)).toBe(hash);
});
// test('getRandom', () => {
//     expect(crypto.getRandom)
//     // 32 bytes long
//     // unique each time 
// })
test('read', () => {
    const buffer = Buffer.from(hash, 'hex');
    const readable = '00ba5188...';
    expect(main_1.default.read(buffer)).toBe(readable);
});
test('verifyHash', () => {
    expect(main_1.default.verifyHash(hash, value)).toBe(true);
    expect(main_1.default.verifyHash(hash, falseValue)).toBe(false);
});
test('stringify', () => {
    const stringInput = 'test';
    const stringOutput = 'test';
    expect(main_1.default.stringify(stringInput)).toBe(stringOutput);
    const arrayInput = [1, 'abc', 'signature'];
    const arrayOutput = "1,abc,signature";
    expect(main_1.default.stringify(arrayInput)).toBe(arrayOutput);
    const objectInput = {
        test: 'data',
        some: [1, 2, 3]
    };
    const objectOutput = '{"test":"data","some":[1, 2, 3]}';
    expect(main_1.default.stringify(arrayInput)).toBe(arrayOutput);
});
test('verifyDate', () => {
    const range = 600000;
    const testDate = Date.now();
    const validEarly = testDate - 599000;
    expect(main_1.default.verifyDate(validEarly, range)).toBe(true);
    const validLate = testDate + 599000;
    expect(main_1.default.verifyDate(validLate, range)).toBe(true);
    const invalidEarly = testDate - 601000;
    expect(main_1.default.verifyDate(invalidEarly, range)).toBe(false);
    const invalidLate = testDate + 601000;
    expect(main_1.default.verifyDate(invalidLate, range)).toBe(false);
});
// test('generateKeys',() => {
// })
//# sourceMappingURL=main.test.js.map