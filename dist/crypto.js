"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
const openpgp = require('openpgp');
const aesjs = require('aes-js');
const XXH = require('xxhashjs');
// TODO
// replace profile with profile object and type def
// replace value with record interfarce
// find or create type declerations for openpgp and aesjs
// implement verifyValue() for SSDB records
// pass in the seed values and passphrase for key generation
// remove/replace PGP padding on keys and signatures
// replace AES-JS with native crypto or openpgp symmetric encryption
// implement parsec consensus for node failures
// use SSCL block hashes in place of time stamps 
function getHash(value) {
    // returns the sha256 hash of a string value
    const hasher = crypto_1.default.createHash('sha256');
    hasher.update(value);
    const hash = hasher.digest('hex');
    return hash;
}
exports.getHash = getHash;
function getHash64(value) {
    const key = 0xABCD;
    const eightByteHash = Buffer.from(XXH.h64(value, key).toString('16'), 'hex');
    return eightByteHash;
}
exports.getHash64 = getHash64;
function isValidHash(hash, value) {
    // checks to ensure a supplied hash matches a value
    const valid = hash === getHash(value);
    return valid;
}
exports.isValidHash = isValidHash;
function getRandom() {
    // generates a random 32 byte symmetric password
    const randomBytes = crypto_1.default.randomBytes(32);
    const randomString = randomBytes.toString('hex');
    return randomString;
}
exports.getRandom = getRandom;
function read(buffer) {
    // takes a hex buffer and returns the condensed human readable form
    const hexString = buffer.toString('hex');
    const readableString = hexString.substring(0, 8).concat('...');
    return readableString;
}
exports.read = read;
function stringify(value) {
    // object and array can be of many types! just a generic encoding function 
    if (typeof value === 'object') {
        if (Array.isArray(value))
            value = value.toString();
        else
            value = JSON.stringify(value);
    }
    return value;
}
exports.stringify = stringify;
function isDateWithinRange(date, range) {
    // checks to ensure a supplied unix timestamp is within a supplied range
    const valid = Math.abs(Date.now() - date) <= range;
    return valid;
}
exports.isDateWithinRange = isDateWithinRange;
function generateKeys(name, email, passphrase) {
    // generate an ECDSA key pair with openpgp
    return new Promise(async (resolve, reject) => {
        try {
            const options = {
                userIds: [{
                        name: name,
                        email: email
                    }],
                curve: 'ed25519',
                passphrase: passphrase
            };
            const keys = await openpgp.generateKey(options);
            resolve(keys);
        }
        catch (error) {
            reject(error);
        }
    });
}
exports.generateKeys = generateKeys;
function getPrivateKeyObject(privateKey, passphrase) {
    return new Promise(async (resolve, reject) => {
        // extracts the private key object for signature and encryption
        try {
            const privateKeyObject = (await openpgp.key.readArmored(privateKey)).keys[0];
            await privateKeyObject.decrypt(passphrase);
            resolve(privateKeyObject);
        }
        catch (error) {
            reject(error);
        }
    });
}
exports.getPrivateKeyObject = getPrivateKeyObject;
function sign(value, privateKeyObject) {
    // cannot figure out the type for privateKeyObject and openpgp does not have a defined type
    // creates a detached signature given a value and a private key
    return new Promise(async (resolve, reject) => {
        try {
            const data = stringify(value);
            const options = {
                message: openpgp.cleartext.fromText(value),
                privateKeys: [privateKeyObject],
                detached: true
            };
            const signed = await openpgp.sign(options);
            const signature = signed.signature;
            resolve(signature);
        }
        catch (error) {
            reject(error);
        }
    });
}
exports.sign = sign;
function isValidSignature(value, signature, publicKey) {
    // verifies a detached signature on a message given a public key for
    // RPC message signatures
    // Join, Leave, and Failure proofs (LHT entries)
    // SSDB record signatures 
    return new Promise(async (resolve, reject) => {
        try {
            const message = stringify(value);
            const options = {
                message: openpgp.message.fromText(message),
                signature: openpgp.signature.readArmored(signature),
                publicKeys: openpgp.key.readArmored(publicKey).keys
            };
            const verified = await openpgp.verify(options);
            const valid = verified.signatures[0].valid;
            resolve(valid);
        }
        catch (error) {
            reject(error);
        }
    });
}
exports.isValidSignature = isValidSignature;
async function createJoinProof(profile) {
    // how would you import the profile interface from @subspace/profile?
    // creates a signed proof from a host node, showing they have joined the LHT 
    try {
        const data = [
            profile.hexId,
            profile.publicKey,
            Date.now()
        ];
        const signature = await sign(data, profile.privateKeyObject);
        data.push(signature);
        return data;
    }
    catch (error) {
        console.log('Error creating join proof');
        console.log(error);
        return (error);
    }
}
exports.createJoinProof = createJoinProof;
async function isValidJoinProof(data) {
    // verifies a join proof received from another node or when validating a LHT received over sync()
    try {
        const validity = {
            isValid: true,
            reply: {
                type: null,
                data: null
            },
        };
        const hexId = data[0];
        const publicKey = data[1];
        const timeStamp = data[2];
        const signature = data[3];
        const message = data.slice(0, 3);
        if (!isValidHash(hexId, publicKey)) {
            validity.isValid = false;
            validity.reply.type = 'join error';
            validity.reply.data = '--- Invalid Hash ---';
        }
        if (!isDateWithinRange(timeStamp, 600000)) {
            validity.isValid = false;
            validity.reply.type = 'join error';
            validity.reply.data = '--- Invalid Timestamp ---';
        }
        if (!await isValidSignature(message, signature, publicKey)) {
            validity.isValid = false;
            validity.reply.type = 'join error';
            validity.reply.data = '--- Invalid Signature ---';
        }
        return validity;
    }
    catch (error) {
        console.log('Error verifying join proof');
        console.log(error);
        return (error);
    }
}
exports.isValidJoinProof = isValidJoinProof;
async function createLeaveProof(profile) {
    // allows a peer to announce they have left the network as part of a graceful shutdown
    try {
        const data = [
            profile.hexId,
            Date.now()
        ];
        const signature = await sign(data, profile.privateKeyObject);
        data.push(signature);
        return data;
    }
    catch (error) {
        console.log('Error generating a leave proof');
        console.log(error);
        return (error);
    }
}
exports.createLeaveProof = createLeaveProof;
async function isValidLeaveProof(data, publicKey) {
    // verifies a leave proof received from another node or when validating an LHT received over sync 
    try {
        const validity = {
            isValid: true,
            reply: {
                type: null,
                data: null
            },
        };
        const hexId = data[0];
        const timeStamp = data[1];
        const signature = data[2];
        const message = data.slice(0, 2);
        if (!isDateWithinRange(timeStamp, 600000)) {
            validity.isValid = false;
            validity.reply.type = 'leave error';
            validity.reply.data = '--- Invalid Timestamp ---';
        }
        if (!isValidSignature(message, signature, publicKey)) {
            validity.isValid = false;
            validity.reply.type = 'leave error';
            validity.reply.data = '--- Invalid Signature ---';
        }
        return validity;
    }
    catch (error) {
        console.log('Error verifying leave proof');
        console.log(error);
        return (error);
    }
}
exports.isValidLeaveProof = isValidLeaveProof;
async function createFailureProof(peerId, profile) {
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
        return (error);
    }
}
exports.createFailureProof = createFailureProof;
async function isValidFailureProof(data, publicKey) {
    // PBFT 2/3 vote for now
    // will implement the parsec consensus protocol as a separate module later
    try {
        // called when a failure message is received
        // validates the message and updates the tally in members
    }
    catch (error) {
        console.log('Error validating failure proof');
        console.log(error);
        return (error);
    }
}
exports.isValidFailureProof = isValidFailureProof;
function encryptAssymetric(value, publicKey) {
    // encrypt a symmetric key with a private key
    return new Promise(async (resolve, reject) => {
        try {
            const options = {
                data: value,
                publicKeys: openpgp.key.readArmored(publicKey).keys
            };
            const cipherText = await openpgp.encrypt(options);
            const encryptedValue = cipherText.data;
            resolve(encryptedValue);
        }
        catch (error) {
            reject(error);
        }
    });
}
exports.encryptAssymetric = encryptAssymetric;
function decryptAssymetric(value, privateKeyObject) {
    // decrypt a symmetric key with a private key
    return new Promise(async (resolve, reject) => {
        try {
            const options = {
                message: openpgp.message.readArmored(value),
                privateKeys: [privateKeyObject]
            };
            const plainText = await openpgp.decrypt(options);
            const decryptedValue = plainText.data;
            resolve(decryptedValue);
        }
        catch (error) {
            reject(error);
        }
    });
}
exports.decryptAssymetric = decryptAssymetric;
function encryptSymmetric(value, symkey) {
    // encrypts a record value with a symmetric key
    return new Promise(async (resolve, reject) => {
        try {
            const key = Buffer.from(symkey, 'hex');
            const byteValue = aesjs.utils.utf8.toBytes(value);
            const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
            // an insanely compplex object, feel free to add an interface!
            const encryptedBytes = aesCtr.encrypt(byteValue);
            const encryptedHex = aesjs.utils.hex.fromBytes(encryptedBytes);
            resolve(encryptedHex);
        }
        catch (error) {
            reject(error);
        }
    });
}
exports.encryptSymmetric = encryptSymmetric;
function decryptSymmetric(encryptedValue, symkey) {
    // decrypts a record value with a symmetric key
    return new Promise(async (resolve, reject) => {
        try {
            const key = Buffer.from(symkey, 'hex');
            const encryptedBytes = aesjs.utils.hex.toBytes(encryptedValue);
            const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
            // an insanely compplex object, feel free to add an interface!
            const decryptedBytes = aesCtr.decrypt(encryptedBytes);
            const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
            resolve(decryptedText);
        }
        catch (error) {
            reject(error);
        }
    });
}
exports.decryptSymmetric = decryptSymmetric;
//# sourceMappingURL=crypto.js.map