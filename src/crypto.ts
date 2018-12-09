import * as crypto from 'crypto'
import * as interfaces from './interfaces'
const openpgp = require('openpgp')
const aesjs = require('aes-js')
const XXH = require('xxhashjs')

export {jumpConsistentHash} from '@subspace/jump-consistent-hash'
export {Destination as rendezvousHashDestination, pickDestinations as rendezvousHashPickDestinations} from '@subspace/rendezvous-hash'

const BYTES_PER_HASH = 1000000    // one hash per MB of pledge for simple proof of space, 32 eventually

export function constantTimeEqual<T extends string>(expected: T, test: T): boolean;
export function constantTimeEqual<T extends Uint8Array>(expected: T, test: T): boolean;
export function constantTimeEqual(expected: string | Uint8Array, test: typeof expected): boolean {
  // @ts-ignore Bug in TypeScript: https://github.com/Microsoft/TypeScript/issues/14107
  const expectedBuffer = Buffer.from(expected);
  // @ts-ignore Bug in TypeScript: https://github.com/Microsoft/TypeScript/issues/14107
  const testBuffer = Buffer.from(test);
  if (expectedBuffer.length !== testBuffer.length) {
    // If lengths are different - make fake comparison just to have constant time, since `crypto.timingSafeEqual` doesn't work with buffers of different length
    return crypto.timingSafeEqual(
      Buffer.from('0'.repeat(expected.length)),
      Buffer.from('1'.repeat(expected.length)),
    );
  }
  return crypto.timingSafeEqual(expectedBuffer, testBuffer);
}


// TODO
  // replace profile with profile object and type def
  // replace value with record interface
  // find or create type declarations for openpgp and aesjs
  // implement verifyValue() for SSDB records
  // pass in the seed values and passphrase for key generation
  // remove/replace PGP padding on keys and signatures
  // replace AES-JS with native crypto or openpgp symmetric encryption
  // implement parsec consensus for node failures
  // use SSCL block hashes in place of time stamps

export function getHash(value: string): string;
export function getHash<Uint8Array>(value: Uint8Array): Uint8Array;
export function getHash(value: string | Uint8Array): typeof value {
  // returns the sha256 hash of a string value
  const hasher = crypto.createHash('sha256')
  hasher.update(value)
  if (typeof value === 'string') {
    return hasher.digest('hex')
  }
  return hasher.digest()
}

export function getHash64(value: string) {
  const key = 0xABCD
  return Buffer.from(XXH.h64(value, key).toString('16'), 'hex')
}

export function isValidHash<T extends string>(hash: T, value: T): boolean;
export function isValidHash<T extends Uint8Array>(hash: T, value: T): boolean;
export function isValidHash(hash: string | Uint8Array, value: string | Uint8Array): boolean {
  // checks to ensure a supplied hash matches a value
  // @ts-ignore Bug in TypeScript: https://github.com/Microsoft/TypeScript/issues/14107
  return constantTimeEqual(hash, getHash(value))
}

export function getRandom() {
  // generates a random 32 byte symmetric password
  const randomBytes = crypto.randomBytes(32)
  return randomBytes.toString('hex')
}

export function read(buffer: Buffer) {
  // takes a hex buffer and returns the condensed human readable form
  const hexString = buffer.toString('hex')
  return hexString.substring(0, 8).concat('...')
}

/**
 * @deprecated Use `JSON.stringify()` instead, this will be removed in future
 */
export function stringify(value: any) {
  return JSON.stringify(value)
}

export function isDateWithinRange(date: number, range: number) {
  // checks to ensure a supplied unix timestamp is within a supplied range
  return Math.abs(Date.now() - date) <= range
}

export async function generateKeys(name: string, email: string, passphrase: string) {

  const options: interfaces.optionsObject = {
    userIds: [{
      name: name,
      email: email
    }],
    curve: 'ed25519',
    passphrase: passphrase
  }

  return await openpgp.generateKey(options)
}

export async function getPrivateKeyObject(privateKey: string, passphrase: string) {
  const privateKeyObject = (await openpgp.key.readArmored(privateKey)).keys[0]
  await privateKeyObject.decrypt(passphrase)
  return privateKeyObject
}

export async function sign(value: string | object | any[], privateKeyObject: any): Promise<string>;
export async function sign(value: Uint8Array, privateKeyObject: any): Promise<Uint8Array>;
export async function sign(value: string | Uint8Array | object | any[], privateKeyObject: any): Promise<string | Uint8Array> {
  if (value instanceof Uint8Array) {
    const options: interfaces.signatureOptions = {
      message: openpgp.message.fromBinary(value),
      privateKeys: [privateKeyObject],
      detached: true
    }

    const signed: interfaces.signatureValue = await openpgp.sign(options)
    return Buffer.from(signed.signature, 'hex')
  } else {
    const data = JSON.stringify(value)

    const options: interfaces.signatureOptions = {
      message: openpgp.cleartext.fromText(data),
      privateKeys: [privateKeyObject],
      detached: true
    }

    const signed: interfaces.signatureValue = await openpgp.sign(options)
    return signed.signature
  }
}

export async function isValidSignature(value: string | object | any[], signature: string, publicKey: string): Promise<boolean>;
export async function isValidSignature(value: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
export async function isValidSignature(value: string | Uint8Array | object | any[], signature: string | Uint8Array, publicKey: string | Uint8Array): Promise<boolean> {
  // verifies a detached signature on a message given a public key for
    // RPC message signatures
    // Join, Leave, and Failure proofs (LHT entries)
    // SSDB record signatures
  if (value instanceof Uint8Array && signature instanceof Uint8Array && publicKey instanceof Uint8Array) {
    const options: interfaces.verifySignatureOptions  = {
      message: openpgp.message.fromBinary(value),
      signature: await openpgp.signature.readArmored(Buffer.from(signature).toString('hex')),
      publicKeys: (await openpgp.key.readArmored(Buffer.from(publicKey).toString('hex'))).keys
    }

    const verified: openpgp.VerifiedMessage = await openpgp.verify(options)
    return verified.signatures[0].valid
  } else {
    const message = JSON.stringify(value)

    const options: interfaces.verifySignatureOptions  = {
      message: openpgp.cleartext.fromText(message),
      signature: await openpgp.signature.readArmored(signature),
      publicKeys: (await openpgp.key.readArmored(publicKey)).keys
    }

    const verified: openpgp.VerifiedMessage = await openpgp.verify(options)
    return verified.signatures[0].valid
  }
}

export function createProofOfSpace(seed: string, size: number) {
  // create a mock proof of space to represent your disk plot

  const plot: Set<string> = new Set()
  const plotSize = size / BYTES_PER_HASH

  for(let i = 0; i < plotSize; i++) {
    seed = getHash(seed)
    plot.add(seed)
  }

  return {
    id: getHash(JSON.stringify(plot)),
    createdAt: Date.now(),
    size,
    seed,
    plot
  }
}

export function isValidProofOfSpace(key: string, size: number, proofId: string) {
  // validates a mock proof of space
  return constantTimeEqual(proofId, createProofOfSpace(key, size).id)
}

export function createProofOfTime(seed: string) {
  // create a mock proof of time by converting a hex seed string into time in ms
  let time = 0
  for (let char of seed) {
    time += parseInt(char, 16) + 1
  }
  return time * 1000
}

export function isValidProofOfTime(seed: string, time: number) {
  // validate a given proof of time
  return time === createProofOfTime(seed)
}

export async function isValidMessageSignature(message: any) {
  let detachedMessage = JSON.parse(JSON.stringify(message))
  detachedMessage.signature = null
  return await isValidSignature(detachedMessage, message.signature, message.publicKey)
}

export async function createJoinProof(profile: any) {
  // how would you import the profile interface from @subspace/profile?
  // creates a signed proof from a host node, showing they have joined the LHT

  const data: any[] = [
    profile.hexId,
    profile.publicKey,
    Date.now()
  ]

  const signature: string = await sign(data, profile.privateKeyObject )
  data.push(signature)
  return data
}

export async function isValidJoinProof(data: any[]) {
  // verifies a join proof received from another node or when validating a LHT received over sync()

  const validity: interfaces.validityValue = {
    isValid: true,
    reply: {
      type: null,
      data: null
    },
  }

  const hexId: string = data[0]
  const publicKey: string = data[1]
  const timeStamp: number = data[2]
  const signature: string = data[3]
  const message: any[] = data.slice(0,3)

  if(!isValidHash(hexId, publicKey)) {
    validity.isValid = false
    validity.reply.type = 'join error'
    validity.reply.data = '--- Invalid Hash ---'
  }

  if(!isDateWithinRange(timeStamp, 600000)) {
    validity.isValid = false
    validity.reply.type = 'join error'
    validity.reply.data = '--- Invalid Timestamp ---'
  }

  if(!await isValidSignature(message, signature, publicKey)) {
    validity.isValid = false
    validity.reply.type = 'join error'
    validity.reply.data = '--- Invalid Signature ---'
  }

  return validity
}

export async function createLeaveProof(profile: any) {
  // allows a peer to announce they have left the network as part of a graceful shutdown

  const data: any[] = [
    profile.hexId,
    Date.now()
  ]

  const signature: string = await sign(data, profile.privateKeyObject)
  data.push(signature)
  return data
}

export async function isValidLeaveProof(data: any[], publicKey: string) {
  // verifies a leave proof received from another node or when validating an LHT received over sync

  const validity: interfaces.validityValue = {
    isValid: true,
    reply: {
      type: null,
      data: null
    },
  }

  const hexId: string = data[0]
  const timeStamp: number = data[1]
  const signature: string = data[2]
  const message: any = data.slice(0,2)

  if(!isDateWithinRange(timeStamp, 600000)) {
    validity.isValid = false
    validity.reply.type = 'leave error'
    validity.reply.data = '--- Invalid Timestamp ---'
  }

  if (!isValidSignature(message, signature, publicKey)) {
    validity.isValid = false
    validity.reply.type = 'leave error'
    validity.reply.data = '--- Invalid Signature ---'
  }

  return validity
}

export async function createFailureProof(peerId: string, profile: any) {
  // PBFT 2/3 vote for now
  // will implement the parsec consensus protocol as a separate module later

  // called from a higher module on a disconnect event, if the node is still in the LHT
  // vote that the node has failed
  // check routing table for a list of all neighbors
  // send vote to all neighbors
  // maintain a tally in members and decide once all votes have been cast
}

export async function isValidFailureProof(data: any[], publicKey: string) {
  // PBFT 2/3 vote for now
  // will implement the parsec consensus protocol as a separate module later

  // called when a failure message is received
  // validates the message and updates the tally in members
}

export async function encryptAssymetric(value: string, publicKey: string) {
  // encrypt a symmetric key with a private key
  const options: interfaces.encryptionOptions = {
    data: value,
    publicKeys: openpgp.key.readArmored(publicKey).keys
  }

  const cipherText: interfaces.encryptedValueObject = await openpgp.encrypt(options)
  return cipherText.data


}

export async function decryptAssymetric(value: string, privateKeyObject: object) {
  // decrypt a symmetric key with a private key

  const options: interfaces.decryptionOptions = {
    message: openpgp.message.readArmored(value),
    privateKeys: [privateKeyObject]
  }

  const plainText: interfaces.decrpytedValueObject = await openpgp.decrypt(options)
  return plainText.data
}

export function encryptSymmetric(value: string, symkey: string) {
  // encrypts a record value with a symmetric key
  const key: Buffer = Buffer.from(symkey, 'hex')
  const byteValue: Uint8Array[] = aesjs.utils.utf8.toBytes(value)
  const aesCtr: any = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5))
  const encryptedBytes: Uint8Array[] = aesCtr.encrypt(byteValue)
  return aesjs.utils.hex.fromBytes(encryptedBytes)
}

export function decryptSymmetric(encryptedValue: string, symkey: string) {
  // decrypts a record value with a symmetric key
  const key: Buffer = Buffer.from(symkey, 'hex')
  const encryptedBytes: Uint8Array[] = aesjs.utils.hex.toBytes(encryptedValue)
  const aesCtr: any = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5))
  const decryptedBytes: Uint8Array[] = aesCtr.decrypt(encryptedBytes)
  const decryptedText: string = aesjs.utils.utf8.fromBytes(decryptedBytes)
  return decryptedText
}
