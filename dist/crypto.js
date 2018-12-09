(function (factory) {
    if (typeof module === "object" && typeof module.exports === "object") {
        var v = factory(require, exports);
        if (v !== undefined) module.exports = v;
    }
    else if (typeof define === "function" && define.amd) {
        define(["require", "exports", "crypto", "@subspace/jump-consistent-hash", "@subspace/rendezvous-hash"], factory);
    }
})(function (require, exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    const crypto = require("crypto");
    const openpgp = require('openpgp');
    const aesjs = require('aes-js');
    const XXH = require('xxhashjs');
    var jump_consistent_hash_1 = require("@subspace/jump-consistent-hash");
    exports.jumpConsistentHash = jump_consistent_hash_1.jumpConsistentHash;
    var rendezvous_hash_1 = require("@subspace/rendezvous-hash");
    exports.rendezvousHashDestination = rendezvous_hash_1.Destination;
    exports.rendezvousHashPickDestinations = rendezvous_hash_1.pickDestinations;
    const BYTES_PER_HASH = 1000000; // one hash per MB of pledge for simple proof of space, 32 eventually
    function constantTimeEqual(expected, test) {
        // @ts-ignore Bug in TypeScript: https://github.com/Microsoft/TypeScript/issues/14107
        const expectedBuffer = Buffer.from(expected);
        // @ts-ignore Bug in TypeScript: https://github.com/Microsoft/TypeScript/issues/14107
        const testBuffer = Buffer.from(test);
        if (expectedBuffer.length !== testBuffer.length) {
            // If lengths are different - make fake comparison just to have constant time, since `crypto.timingSafeEqual` doesn't work with buffers of different length
            return crypto.timingSafeEqual(Buffer.from('0'.repeat(expected.length)), Buffer.from('1'.repeat(expected.length)));
        }
        return crypto.timingSafeEqual(expectedBuffer, testBuffer);
    }
    exports.constantTimeEqual = constantTimeEqual;
    function getHash(value) {
        // returns the sha256 hash of a string value
        const hasher = crypto.createHash('sha256');
        hasher.update(value);
        if (typeof value === 'string') {
            return hasher.digest('hex');
        }
        return hasher.digest();
    }
    exports.getHash = getHash;
    function getHash64(value) {
        const key = 0xABCD;
        return Buffer.from(XXH.h64(value, key).toString('16'), 'hex');
    }
    exports.getHash64 = getHash64;
    function isValidHash(hash, value) {
        // checks to ensure a supplied hash matches a value
        // @ts-ignore Bug in TypeScript: https://github.com/Microsoft/TypeScript/issues/14107
        return constantTimeEqual(hash, getHash(value));
    }
    exports.isValidHash = isValidHash;
    function getRandom() {
        // generates a random 32 byte symmetric password
        const randomBytes = crypto.randomBytes(32);
        return randomBytes.toString('hex');
    }
    exports.getRandom = getRandom;
    function read(buffer) {
        // takes a hex buffer and returns the condensed human readable form
        const hexString = buffer.toString('hex');
        return hexString.substring(0, 8).concat('...');
    }
    exports.read = read;
    /**
     * @deprecated Use `JSON.stringify()` instead, this will be removed in future
     */
    function stringify(value) {
        return JSON.stringify(value);
    }
    exports.stringify = stringify;
    function isDateWithinRange(date, range) {
        // checks to ensure a supplied unix timestamp is within a supplied range
        return Math.abs(Date.now() - date) <= range;
    }
    exports.isDateWithinRange = isDateWithinRange;
    async function generateKeys(name, email, passphrase) {
        const options = {
            userIds: [{
                    name: name,
                    email: email
                }],
            curve: 'ed25519',
            passphrase: passphrase
        };
        return await openpgp.generateKey(options);
    }
    exports.generateKeys = generateKeys;
    async function getPrivateKeyObject(privateKey, passphrase) {
        const privateKeyObject = (await openpgp.key.readArmored(privateKey)).keys[0];
        await privateKeyObject.decrypt(passphrase);
        return privateKeyObject;
    }
    exports.getPrivateKeyObject = getPrivateKeyObject;
    async function sign(value, privateKeyObject) {
        if (value instanceof Uint8Array) {
            const options = {
                message: openpgp.message.fromBinary(value),
                privateKeys: [privateKeyObject],
                detached: true
            };
            const signed = await openpgp.sign(options);
            return Buffer.from(signed.signature, 'hex');
        }
        else {
            const data = JSON.stringify(value);
            const options = {
                message: openpgp.cleartext.fromText(data),
                privateKeys: [privateKeyObject],
                detached: true
            };
            const signed = await openpgp.sign(options);
            return signed.signature;
        }
    }
    exports.sign = sign;
    async function isValidSignature(value, signature, publicKey) {
        // verifies a detached signature on a message given a public key for
        // RPC message signatures
        // Join, Leave, and Failure proofs (LHT entries)
        // SSDB record signatures
        if (value instanceof Uint8Array && signature instanceof Uint8Array && publicKey instanceof Uint8Array) {
            const options = {
                message: openpgp.message.fromBinary(value),
                signature: await openpgp.signature.readArmored(Buffer.from(signature).toString('hex')),
                publicKeys: (await openpgp.key.readArmored(Buffer.from(publicKey).toString('hex'))).keys
            };
            const verified = await openpgp.verify(options);
            return verified.signatures[0].valid;
        }
        else {
            const message = JSON.stringify(value);
            const options = {
                message: openpgp.cleartext.fromText(message),
                signature: await openpgp.signature.readArmored(signature),
                publicKeys: (await openpgp.key.readArmored(publicKey)).keys
            };
            const verified = await openpgp.verify(options);
            return verified.signatures[0].valid;
        }
    }
    exports.isValidSignature = isValidSignature;
    function createProofOfSpace(seed, size) {
        // create a mock proof of space to represent your disk plot
        const plot = new Set();
        const plotSize = size / BYTES_PER_HASH;
        for (let i = 0; i < plotSize; i++) {
            seed = getHash(seed);
            plot.add(seed);
        }
        return {
            id: getHash(JSON.stringify(plot)),
            createdAt: Date.now(),
            size,
            seed,
            plot
        };
    }
    exports.createProofOfSpace = createProofOfSpace;
    function isValidProofOfSpace(key, size, proofId) {
        // validates a mock proof of space
        return constantTimeEqual(proofId, createProofOfSpace(key, size).id);
    }
    exports.isValidProofOfSpace = isValidProofOfSpace;
    function createProofOfTime(seed) {
        // create a mock proof of time by converting a hex seed string into time in ms
        let time = 0;
        for (let char of seed) {
            time += parseInt(char, 16) + 1;
        }
        return time * 1000;
    }
    exports.createProofOfTime = createProofOfTime;
    function isValidProofOfTime(seed, time) {
        // validate a given proof of time
        return time === createProofOfTime(seed);
    }
    exports.isValidProofOfTime = isValidProofOfTime;
    async function isValidMessageSignature(message) {
        let detachedMessage = JSON.parse(JSON.stringify(message));
        detachedMessage.signature = null;
        return await isValidSignature(detachedMessage, message.signature, message.publicKey);
    }
    exports.isValidMessageSignature = isValidMessageSignature;
    async function createJoinProof(profile) {
        // how would you import the profile interface from @subspace/profile?
        // creates a signed proof from a host node, showing they have joined the LHT
        const data = [
            profile.hexId,
            profile.publicKey,
            Date.now()
        ];
        const signature = await sign(data, profile.privateKeyObject);
        data.push(signature);
        return data;
    }
    exports.createJoinProof = createJoinProof;
    async function isValidJoinProof(data) {
        // verifies a join proof received from another node or when validating a LHT received over sync()
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
    exports.isValidJoinProof = isValidJoinProof;
    async function createLeaveProof(profile) {
        // allows a peer to announce they have left the network as part of a graceful shutdown
        const data = [
            profile.hexId,
            Date.now()
        ];
        const signature = await sign(data, profile.privateKeyObject);
        data.push(signature);
        return data;
    }
    exports.createLeaveProof = createLeaveProof;
    async function isValidLeaveProof(data, publicKey) {
        // verifies a leave proof received from another node or when validating an LHT received over sync
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
    exports.isValidLeaveProof = isValidLeaveProof;
    async function createFailureProof(peerId, profile) {
        // PBFT 2/3 vote for now
        // will implement the parsec consensus protocol as a separate module later
        // called from a higher module on a disconnect event, if the node is still in the LHT
        // vote that the node has failed
        // check routing table for a list of all neighbors
        // send vote to all neighbors
        // maintain a tally in members and decide once all votes have been cast
    }
    exports.createFailureProof = createFailureProof;
    async function isValidFailureProof(data, publicKey) {
        // PBFT 2/3 vote for now
        // will implement the parsec consensus protocol as a separate module later
        // called when a failure message is received
        // validates the message and updates the tally in members
    }
    exports.isValidFailureProof = isValidFailureProof;
    async function encryptAssymetric(value, publicKey) {
        // encrypt a symmetric key with a private key
        const options = {
            data: value,
            publicKeys: openpgp.key.readArmored(publicKey).keys
        };
        const cipherText = await openpgp.encrypt(options);
        return cipherText.data;
    }
    exports.encryptAssymetric = encryptAssymetric;
    async function decryptAssymetric(value, privateKeyObject) {
        // decrypt a symmetric key with a private key
        const options = {
            message: openpgp.message.readArmored(value),
            privateKeys: [privateKeyObject]
        };
        const plainText = await openpgp.decrypt(options);
        return plainText.data;
    }
    exports.decryptAssymetric = decryptAssymetric;
    function encryptSymmetric(value, symkey) {
        // encrypts a record value with a symmetric key
        const key = Buffer.from(symkey, 'hex');
        const byteValue = aesjs.utils.utf8.toBytes(value);
        const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
        const encryptedBytes = aesCtr.encrypt(byteValue);
        return aesjs.utils.hex.fromBytes(encryptedBytes);
    }
    exports.encryptSymmetric = encryptSymmetric;
    function decryptSymmetric(encryptedValue, symkey) {
        // decrypts a record value with a symmetric key
        const key = Buffer.from(symkey, 'hex');
        const encryptedBytes = aesjs.utils.hex.toBytes(encryptedValue);
        const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
        const decryptedBytes = aesCtr.decrypt(encryptedBytes);
        const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
        return decryptedText;
    }
    exports.decryptSymmetric = decryptSymmetric;
});
//# sourceMappingURL=crypto.js.map