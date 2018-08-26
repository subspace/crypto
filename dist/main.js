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
const crypto_1 = __importDefault(require("crypto"));
const openpgp = require('openpgp');
const aesjs = require('aes-js');
// TODO
// implement verifyValue() for SSDB records
// remove/replace PGP padding on keys and signatures
// replace AES-JS with native crypto or openpgp symmetric encryption
// implement parsec consensus for node failures
// use SSCL block hashes in place of time stamps 
const Crypto = {
    getHash: (value) => {
        // returns the sha256 hash of a string value
        const hasher = crypto_1.default.createHash('sha256');
        hasher.update(value);
        const hash = hasher.digest('hex');
        return hash;
    },
    sha256: (buffer) => {
        // custom hash function for BitTorrent DHT
        return Crypto.getHash(buffer);
    },
    getRandom: () => {
        // generates a random 32 byte symmetric password
        const randomBytes = crypto_1.default.randomBytes(32);
        const randomString = randomBytes.toString('hex');
        return randomString;
    },
    read: (buffer) => {
        // takes a hex buffer and returns the condensed human readable form
        const hexString = buffer.toString('hex');
        const readableString = hexString.substring(0, 8).concat('...');
        return readableString;
    },
    stringify: (value) => {
        if (typeof value === 'object') {
            if (Array.isArray(value))
                value = value.toString();
            else
                value = JSON.stringify(value);
        }
        return value;
    },
    generateKeys: (options) => __awaiter(this, void 0, void 0, function* () {
        // generate an ECDSA key pair with openpgp
        const keys = yield openpgp.generateKey(options);
        return keys;
    }),
    sign: (value, privateKeyObject) => __awaiter(this, void 0, void 0, function* () {
        // creates a detached signature given a value and a private key
        const data = Crypto.stringify(value);
        const options = {
            data: data,
            privateKeys: [privateKeyObject],
            detached: true
        };
        const signed = yield openpgp.sign(options);
        const signature = signed.signature;
        return signature;
    }),
    verifySignature: (value, signature, publicKey) => __awaiter(this, void 0, void 0, function* () {
        // verifies a detached signature on a message given a public key for
        // RPC message signatures
        // Join, Leave, and Failure proofs (LHT entries)
        // SSDB record signatures 
        const message = Crypto.stringify(value);
        const options = {
            message: openpgp.message.fromText(message),
            signature: openpgp.signature.readArmored(signature),
            publicKeys: openpgp.key.readArmored(publicKey).keys
        };
        const verified = yield openpgp.verify(options);
        const valid = verified.signatures[0].valid;
        return valid;
    }),
    verifyHash: (hash, value) => {
        // checks to ensure a supplied hash matches a value
        const valid = hash === Crypto.getHash(value);
        return valid;
    },
    verifyDate: (date, range) => {
        // checks to ensure a supplied unix timestamp is within a supplied range
        const valid = Math.abs(Date.now() - date) <= range;
        return valid;
    },
    createJoinProof: (profile) => __awaiter(this, void 0, void 0, function* () {
        // creates a signed proof from a host node, showing they have joined the LHT 
        const data = [
            profile.hexId,
            profile.publicKey,
            Date.now()
        ];
        const signature = yield Crypto.sign(data, profile.privateKeyObject);
        data.push(signature);
        return data;
    }),
    verifyJoinProof: (data) => __awaiter(this, void 0, void 0, function* () {
        // verifies a join proof received from another node or when validating a LHT received over sync()
        const validity = {
            isValid: true,
            reply: {}
        };
        const hexId = data[0];
        const publicKey = data[1];
        const timeStamp = data[2];
        const signature = data[3];
        const message = data.slice(0, 3);
        if (!Crypto.verifyHash(hexId, publicKey)) {
            validity.isValid = false;
            validity.reply.type = 'join error';
            validity.reply.data = '--- Invalid Hash ---';
        }
        if (!Crypto.verifyDate(timeStamp, 600000)) {
            validity.isValid = false;
            validity.reply.type = 'join error';
            validity.reply.data = '--- Invalid Timestamp ---';
        }
        if (!(yield Crypto.verifySignature(message, signature, publicKey))) {
            validity.isValid = false;
            validity.reply.type = 'join error';
            validity.reply.data = '--- Invalid Signature ---';
        }
        return validity;
    }),
    createLeaveProof: (profile) => __awaiter(this, void 0, void 0, function* () {
        // allows a peer to announce they have left the network as part of a graceful shutdown
        const data = [
            profile.hexId,
            Date.now()
        ];
        const signature = yield Crypto.sign(data, profile.privateKeyObject);
        data.push(signature);
        return data;
    }),
    verifyLeaveProof: (data, publicKey) => __awaiter(this, void 0, void 0, function* () {
        // verifies a leave proof received from another node or when validating an LHT received over sync 
        const validity = {
            isValid: true,
            reply: {}
        };
        const hexId = data[0];
        const timeStamp = data[1];
        const signature = data[2];
        const message = data.slice(0, 2);
        if (!Crypto.verifyDate(timeStamp, 600000)) {
            validity.valid = false;
            validity.reply.type = 'leave error';
            validity.reply.message = '--- Invalid Timestamp ---';
        }
        if (!Crypto.verifySignature(message, signature, publicKey)) {
            validity.valid = false;
            validity.reply.type = 'leave error';
            validity.reply.message = '--- Invalid Signature ---';
        }
        return validity;
    }),
    createFailureProof: (peerId, profile) => __awaiter(this, void 0, void 0, function* () {
        // TODO
        // implements the parsec consensus protocol
        // probably as a separate module 
    }),
    verifyFailureProof: (data, publicKey) => __awaiter(this, void 0, void 0, function* () {
        // TODO
        // validates the parsec consensus protocol
    }),
    encryptAssymetric: (value, publicKey) => __awaiter(this, void 0, void 0, function* () {
        const options = {
            data: value,
            publicKeys: openpgp.key.readArmored(publicKey).keys
        };
        const cipherText = yield openpgp.encrypt(options);
        const encryptedValue = cipherText.data;
        return encryptedValue;
    }),
    decryptAssymetric: (value, privateKeyObject) => __awaiter(this, void 0, void 0, function* () {
        const options = {
            message: openpgp.message.readArmored(value),
            privateKeys: [privateKeyObject]
        };
        const plainText = yield openpgp.decrypt(options);
        const decryptedValue = plainText.data;
        return decryptedValue;
    }),
    encryptSymmetric: (value, symkey) => __awaiter(this, void 0, void 0, function* () {
        const key = Buffer.from(symkey, 'hex');
        const byteValue = aesjs.utils.utf8.toBytes(value);
        const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
        const encryptedBytes = aesCtr.encrypt(byteValue);
        const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
        return encryptedHex;
    }),
    decryptSymmetric: (encryptedValue, symkey) => __awaiter(this, void 0, void 0, function* () {
        const key = Buffer.from(symkey, 'hex');
        const encryptedBytes = aesjs.utils.hex.toBytes(encryptedValue);
        const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
        const decryptedBytes = aesCtr.decrypt(encryptedBytes);
        const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
        return decryptedText;
    })
};
exports.default = Crypto;
//# sourceMappingURL=main.js.map