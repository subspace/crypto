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
// pass in the seed values and passphrase for key generation
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
    verifyHash: (hash, value) => {
        // checks to ensure a supplied hash matches a value
        const valid = hash === Crypto.getHash(value);
        return valid;
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
    verifyDate: (date, range) => {
        // checks to ensure a supplied unix timestamp is within a supplied range
        const valid = Math.abs(Date.now() - date) <= range;
        return valid;
    },
    generateKeys: (options) => __awaiter(this, void 0, void 0, function* () {
        // generate an ECDSA key pair with openpgp
        try {
            const keys = yield openpgp.generateKey(options);
            return keys;
        }
        catch (error) {
            console.log('Error generating keys');
            console.log(error);
        }
    }),
    getPrivateKeyObject: (privateKey) => __awaiter(this, void 0, void 0, function* () {
        // extracts the private key object for signature and encryption
        try {
            const privateKeyObject = (yield openpgp.key.readArmored(privateKey)).keys[0];
            return privateKeyObject;
        }
        catch (error) {
            console.log('Error getting private key object');
            console.log(error);
        }
    }),
    sign: (value, privateKeyObject) => __awaiter(this, void 0, void 0, function* () {
        // creates a detached signature given a value and a private key
        try {
            const data = Crypto.stringify(value);
            const options = {
                data: data,
                privateKeys: [privateKeyObject],
                detached: true
            };
            const signed = yield openpgp.sign(options);
            const signature = signed.signature;
            return signature;
        }
        catch (error) {
            console.log('Error generating signature');
            console.log(error);
        }
    }),
    verifySignature: (value, signature, publicKey) => __awaiter(this, void 0, void 0, function* () {
        // verifies a detached signature on a message given a public key for
        // RPC message signatures
        // Join, Leave, and Failure proofs (LHT entries)
        // SSDB record signatures 
        try {
            const message = Crypto.stringify(value);
            const options = {
                message: openpgp.message.fromText(message),
                signature: openpgp.signature.readArmored(signature),
                publicKeys: openpgp.key.readArmored(publicKey).keys
            };
            const verified = yield openpgp.verify(options);
            const valid = verified.signatures[0].valid;
            return valid;
        }
        catch (error) {
            console.log('Error verifying signature');
            console.log(error);
        }
    }),
    createJoinProof: (profile) => __awaiter(this, void 0, void 0, function* () {
        // creates a signed proof from a host node, showing they have joined the LHT 
        try {
            const data = [
                profile.hexId,
                profile.publicKey,
                Date.now()
            ];
            const signature = yield Crypto.sign(data, profile.privateKeyObject);
            data.push(signature);
            return data;
        }
        catch (error) {
            console.log('Error creating join proof');
            console.log(error);
        }
    }),
    verifyJoinProof: (data) => __awaiter(this, void 0, void 0, function* () {
        // verifies a join proof received from another node or when validating a LHT received over sync()
        try {
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
        }
        catch (error) {
            console.log('Error verifying join proof');
            console.log(error);
        }
    }),
    createLeaveProof: (profile) => __awaiter(this, void 0, void 0, function* () {
        // allows a peer to announce they have left the network as part of a graceful shutdown
        try {
            const data = [
                profile.hexId,
                Date.now()
            ];
            const signature = yield Crypto.sign(data, profile.privateKeyObject);
            data.push(signature);
            return data;
        }
        catch (error) {
            console.log('Error generating a leave proof');
            console.log(error);
        }
    }),
    verifyLeaveProof: (data, publicKey) => __awaiter(this, void 0, void 0, function* () {
        // verifies a leave proof received from another node or when validating an LHT received over sync 
        try {
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
        }
        catch (error) {
            console.log('Error verifying leave proof');
            console.log(error);
        }
    }),
    createFailureProof: (peerId, profile) => __awaiter(this, void 0, void 0, function* () {
        // PBFT 2/3 vote for now
        // will implement the parsec consensus protocol as a separate module later
        try {
            // called from a higher module on a disconnect event, if the node is still in the LHT
            // vote that the node has failed
            // check routing table for a list of all neighbors
            // send vote to all neighbors
            // maintain a tally in members and decide once all votes have been cast
        }
        catch (error) {
            console.log('Error generating failure proof');
            console.log(error);
        }
    }),
    verifyFailureProof: (data, publicKey) => __awaiter(this, void 0, void 0, function* () {
        // PBFT 2/3 vote for now
        // will implement the parsec consensus protocol as a separate module later
        try {
            // called when a failure message is received
            // validates the message and updates the tally in members
        }
        catch (error) {
            console.log('Error validating failure proof');
            console.log(error);
        }
    }),
    encryptAssymetric: (value, publicKey) => __awaiter(this, void 0, void 0, function* () {
        // encrypt a symmetric key with a private key
        try {
            const options = {
                data: value,
                publicKeys: openpgp.key.readArmored(publicKey).keys
            };
            const cipherText = yield openpgp.encrypt(options);
            const encryptedValue = cipherText.data;
            return encryptedValue;
        }
        catch (error) {
            console.log('Error encrypting symmetric key with private key');
            console.log(error);
        }
    }),
    decryptAssymetric: (value, privateKeyObject) => __awaiter(this, void 0, void 0, function* () {
        // decrypt a symmetric key with a private key
        try {
            const options = {
                message: openpgp.message.readArmored(value),
                privateKeys: [privateKeyObject]
            };
            const plainText = yield openpgp.decrypt(options);
            const decryptedValue = plainText.data;
            return decryptedValue;
        }
        catch (error) {
            console.log('Error decrypting symmetric key with private key');
            console.log(error);
        }
    }),
    encryptSymmetric: (value, symkey) => __awaiter(this, void 0, void 0, function* () {
        // encrypts a record value with a symmetric key
        try {
            const key = Buffer.from(symkey, 'hex');
            const byteValue = aesjs.utils.utf8.toBytes(value);
            const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
            const encryptedBytes = aesCtr.encrypt(byteValue);
            const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
            return encryptedHex;
        }
        catch (error) {
            console.log('Error encrypting record value with symmetric key');
            console.log(error);
        }
    }),
    decryptSymmetric: (encryptedValue, symkey) => __awaiter(this, void 0, void 0, function* () {
        // decrypts a record value with a symmetric key
        try {
            const key = Buffer.from(symkey, 'hex');
            const encryptedBytes = aesjs.utils.hex.toBytes(encryptedValue);
            const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
            const decryptedBytes = aesCtr.decrypt(encryptedBytes);
            const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
            return decryptedText;
        }
        catch (error) {
            console.log('Error decrypting with symmetric key');
            console.log(error);
        }
    }),
    getXorDistance: (a, b) => {
        if (a.length !== b.length)
            throw new Error('Inputs should have the same length');
        var result = new Buffer(a.length);
        for (var i = 0; i < a.length; i++)
            result[i] = a[i] ^ b[i];
        return result;
    }
};
exports.default = Crypto;
//# sourceMappingURL=main.js.map