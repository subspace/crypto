import crypto from 'crypto'
const openpgp = require('openpgp')
const aesjs = require('aes-js')

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

interface Userid {
  name: string,
  email: string
}

export interface optionsObject {
  userIds: Userid[],
  curve: string,
  passphrase: string
}  

interface signatureOptions {
  message: string,
  privateKeys: any[],
  detached: boolean
}

interface signatureValue {
  signature: string
}

interface verifySignatureOptions {
  message: string,
  signature: string,
  publicKeys: string[]
}

interface validityValue {
  isValid: boolean,
  reply: {
    type: string,
    data: string
  }
}

interface encryptionOptions {
  data: string,
  publicKeys: string
}

interface encryptedValueObject {
  data: string,
  signature: string
}

interface decryptionOptions {
  message: string,
  privateKeys: any[]
}

interface decrpytedValueObject {
  data: string
}

export function getHash(value: string) {
  // returns the sha256 hash of a string value
  const hasher = crypto.createHash('sha256')
  hasher.update(value)
  const hash: string = hasher.digest('hex')
  return hash
}

export function verifyHash(hash: string, value: string) {
  // checks to ensure a supplied hash matches a value
  const valid: boolean = hash === getHash(value)
  return valid 
}

export function getRandom() {
  // generates a random 32 byte symmetric password
  const randomBytes: Buffer = crypto.randomBytes(32)
  const randomString: string = randomBytes.toString('hex')
  return randomString
}

export function read(buffer: Buffer) {
  // takes a hex buffer and returns the condensed human readable form
  const hexString: string = buffer.toString('hex')
  const readableString: string = hexString.substring(0,8).concat('...')
  return readableString
}

export function stringify(value: string | object | any[]) {
  // object and array can be of many types! just a generic encoding function 
  if (typeof value === 'object') {
    if (Array.isArray(value)) value = value.toString()
    else value = JSON.stringify(value)
  }
  return value
}

export function verifyDate(date: number, range: number) {
  // checks to ensure a supplied unix timestamp is within a supplied range
  const valid: boolean = Math.abs(Date.now() - date) <= range
  return valid
}

export async function generateKeys(options: optionsObject) {
  // generate an ECDSA key pair with openpgp
  try {
    const keys: openpgp.KeyContainer = await openpgp.generateKey(options)
    return keys 
  } 
  
  catch(error) {
    console.log('Error generating keys')
    console.log(error)
  }
}

export async function getPrivateKeyObject(privateKey: string) {
  // extracts the private key object for signature and encryption
  try {
    const privateKeyObject = (await openpgp.key.readArmored(privateKey)).keys[0]
    await privateKeyObject.decrypt('passphrase')
    return privateKeyObject
  } 

  catch (error) {
    console.log('Error getting private key object')
    console.log(error)
  }
}

export async function sign(value: string | object | any[], privateKeyObject: any) {
  // cannot figure out the type for privateKeyObject and openpgp does not have a defined type
  // creates a detached signature given a value and a private key

  try {
    const data: string = stringify(value)

    const options: signatureOptions = {
      message: openpgp.cleartext.fromText(value),
      privateKeys: [privateKeyObject],
      detached: true
    }

    const signed: signatureValue = await openpgp.sign(options)
    const signature: string = signed.signature
    return signature
  } 

  catch (error) {
    console.log('Error generating signature')
    console.log(error)
  }
}

export async function verifySignature(value: string | object | any[], signature: string, publicKey: string) {

  // verifies a detached signature on a message given a public key for
    // RPC message signatures
    // Join, Leave, and Failure proofs (LHT entries)
    // SSDB record signatures 
  try {
    const message = stringify(value)

    const options: verifySignatureOptions  = {
      message: openpgp.message.fromText(message),
      signature: openpgp.signature.readArmored(signature),
      publicKeys: openpgp.key.readArmored(publicKey).keys
    }

    const verified: openpgp.VerifiedMessage = await openpgp.verify(options)
    const valid: boolean = verified.signatures[0].valid
    return valid
  } 

  catch (error) {
    console.log('Error verifying signature')
    console.log(error)
  }
}

export async function createJoinProof(profile: any) {
  // how would you import the profile interface from @subspace/profile?
  // creates a signed proof from a host node, showing they have joined the LHT 
  try {
    const data: any[] = [
      profile.hexId,
      profile.publicKey,
      Date.now()
    ]

    const signature: string = await sign(data, profile.privateKeyObject )
    data.push(signature)
    return data
  } 

  catch (error) {
    console.log('Error creating join proof')
    console.log(error)
  }
}

export async function verifyJoinProof(data: any[]) {
  // verifies a join proof received from another node or when validating a LHT received over sync()
  try {
    const validity: validityValue = {
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

    if(!verifyHash(hexId, publicKey)) {
      validity.isValid = false
      validity.reply.type = 'join error'
      validity.reply.data = '--- Invalid Hash ---'
    }

    if(!verifyDate(timeStamp, 600000)) {
      validity.isValid = false
      validity.reply.type = 'join error'
      validity.reply.data = '--- Invalid Timestamp ---'
    }

    if(!await verifySignature(message, signature, publicKey)) {
      validity.isValid = false
      validity.reply.type = 'join error'
      validity.reply.data = '--- Invalid Signature ---'
    }

    return validity
  } 

  catch (error) {
    console.log('Error verifying join proof')
    console.log(error)
  }
}

export async function createLeaveProof(profile: any) {
  // allows a peer to announce they have left the network as part of a graceful shutdown
  try {
    const data: any[] = [
      profile.hexId,
      Date.now()
    ]

    const signature: string = await sign(data, profile.privateKeyObject)
    data.push(signature)
    return data
  } 

  catch (error) {
    console.log('Error generating a leave proof')
    console.log(error)
  }
}

export async function verifyLeaveProof(data: any[], publicKey: string) {
  // verifies a leave proof received from another node or when validating an LHT received over sync 
  try {
    const validity: validityValue = {
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

    if(!verifyDate(timeStamp, 600000)) {
      validity.isValid = false
      validity.reply.type = 'leave error'
      validity.reply.data = '--- Invalid Timestamp ---'
    }

    if (!verifySignature(message, signature, publicKey)) {
      validity.isValid = false
      validity.reply.type = 'leave error'
      validity.reply.data = '--- Invalid Signature ---'
    }

    return validity
  } 

  catch (error) {
    console.log('Error verifying leave proof')
    console.log(error)
  }    
}

export async function createFailureProof(peerId: string, profile: any) { 
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
    console.log('Error generating failure proof')
    console.log(error)
  }
}

export async function verifyFailureProof(data: any[], publicKey: string) {
  // PBFT 2/3 vote for now
  // will implement the parsec consensus protocol as a separate module later
  try {
    // called when a failure message is received
    // validates the message and updates the tally in members

  } 

  catch (error) {
    console.log('Error validating failure proof')
    console.log(error)
  }
}

export async function encryptAssymetric(value: string, publicKey: string) {
  // encrypt a symmetric key with a private key
  try {
    const options: encryptionOptions = {
      data: value,
      publicKeys: openpgp.key.readArmored(publicKey).keys
    }

    const cipherText: encryptedValueObject = await openpgp.encrypt(options)
    const encryptedValue: string = cipherText.data
    return encryptedValue
  } 

  catch (error) {
    console.log('Error encrypting symmetric key with private key')
    console.log(error)
  }
}

export async function decryptAssymetric(value: string, privateKeyObject: object) {
  // decrypt a symmetric key with a private key
  try {
    const options: decryptionOptions = {
      message: openpgp.message.readArmored(value),
      privateKeys: [privateKeyObject]
    }

    const plainText: decrpytedValueObject = await openpgp.decrypt(options)
    const decryptedValue: string = plainText.data
    return decryptedValue
  } 

  catch (error) {
    console.log('Error decrypting symmetric key with private key')
    console.log(error)
  }
}

export async function encryptSymmetric(value: string, symkey: string) {
  // encrypts a record value with a symmetric key
  try {
    const key: Buffer = Buffer.from(symkey, 'hex')
    const byteValue: Uint8Array[] = aesjs.utils.utf8.toBytes(value)
    const aesCtr: any = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5))
    // an insanely compplex object, feel free to add an interface!
    const encryptedBytes: Uint8Array[] = aesCtr.encrypt(byteValue)
    const encryptedHex: string = aesjs.utils.hex.fromBytes(encryptedBytes)
    return encryptedHex
  } 

  catch (error) {
    console.log('Error encrypting record value with symmetric key')
    console.log(error)
  }
}

export async function decryptSymmetric(encryptedValue: string, symkey: string) {
  // decrypts a record value with a symmetric key
  try {
    const key: Buffer = Buffer.from(symkey, 'hex')
    const encryptedBytes: Uint8Array[] = aesjs.utils.hex.toBytes(encryptedValue)
    const aesCtr: any = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5))
    // an insanely compplex object, feel free to add an interface!
    const decryptedBytes: Uint8Array[] = aesCtr.decrypt(encryptedBytes)
    const decryptedText: string = aesjs.utils.utf8.fromBytes(decryptedBytes)
    return decryptedText
  } 

  catch (error) {
    console.log('Error decrypting with symmetric key')
    console.log(error)
  }
}

export async function getXorDistance(a: [number], b: [number]) {
  if (a.length !== b.length) throw new Error('Inputs should have the same length')
  var result: any = new Buffer(a.length)
  for (let i = 0; i < a.length; i++) result[i] = a[i] ^ b[i]
  return result
}


