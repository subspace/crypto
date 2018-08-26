"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const main_1 = __importDefault(require("./main"));
const value = 'hello subspace';
const falseValue = 'herro rubrace';
const hash = '00ba5188adff22ee1f8abc61d6e96c371f0d505ec76f90e86d4b0c8748d646bb';
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
//# sourceMappingURL=main.test.js.map