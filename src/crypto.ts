import crypto from 'crypto'
import * as I from './interfaces'
const openpgp = require('openpgp')
const aesjs = require('aes-js')
const XXH = require('xxhashjs')


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

export function getHash(value: string) {
  // returns the sha256 hash of a string value
  const hasher = crypto.createHash('sha256')
  hasher.update(value)
  const hash: string = hasher.digest('hex')
  return hash
}

export function getHash64(value: string) {
  const key = 0xABCD
  const eightByteHash = Buffer.from(XXH.h64(value, key).toString('16'), 'hex')
  return eightByteHash
}

export function isValidHash(hash: string, value: string) {
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

export function isDateWithinRange(date: number, range: number) {
  // checks to ensure a supplied unix timestamp is within a supplied range
  const valid: boolean = Math.abs(Date.now() - date) <= range
  return valid
}

export function generateKeys(name: string, email: string, passphrase: string): Promise<openpgp.KeyContainer> {
  // generate an ECDSA key pair with openpgp
  return new Promise<openpgp.KeyContainer> (async (resolve, reject) => {
    try {
      const options: I.optionsObject = {
        userIds: [{
          name: name,
          email: email
        }],
        curve: 'ed25519',
        passphrase: passphrase
      }
  
      const keys: openpgp.KeyContainer = await openpgp.generateKey(options)
      resolve(keys)
    }
    catch(error) {
      reject(error)
    }
  })
}

export function getPrivateKeyObject(privateKey: string, passphrase: string): Promise<any> {
  return new Promise<any> (async (resolve, reject) => {
    // extracts the private key object for signature and encryption
    try {
      const privateKeyObject = (await openpgp.key.readArmored(privateKey)).keys[0]
      await privateKeyObject.decrypt(passphrase)
      resolve(privateKeyObject)
    }
    catch(error) {
      reject(error)
    }
  })
}

export function sign(value: string | object | any[], privateKeyObject: any): Promise<string> {
  // cannot figure out the type for privateKeyObject and openpgp does not have a defined type
  // creates a detached signature given a value and a private key
  return new Promise <string> (async (resolve, reject) => {
    try {
      const data: string = stringify(value)
  
      const options: I.signatureOptions = {
        message: openpgp.cleartext.fromText(value),
        privateKeys: [privateKeyObject],
        detached: true
      }
  
      const signed: I.signatureValue = await openpgp.sign(options)
      const signature: string = signed.signature
      resolve(signature)
    } 
    catch (error) {
      reject(error)
    }
  })
}

export function isValidSignature(value: string | object | any[], signature: string, publicKey: string): Promise<boolean> {
  // verifies a detached signature on a message given a public key for
    // RPC message signatures
    // Join, Leave, and Failure proofs (LHT entries)
    // SSDB record signatures 
  return new Promise <boolean> (async (resolve, reject) => {
    try {
      const message = stringify(value)
  
      const options: I.verifySignatureOptions  = {
        message: openpgp.message.fromText(message),
        signature: openpgp.signature.readArmored(signature),
        publicKeys: openpgp.key.readArmored(publicKey).keys
      }
  
      const verified: openpgp.VerifiedMessage = await openpgp.verify(options)
      const valid: boolean = verified.signatures[0].valid
      resolve(valid)
    } 
  
    catch (error) {
      reject(error)
    }
  })  
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
    return(error)
  }
}

export async function isValidJoinProof(data: any[]) {
  // verifies a join proof received from another node or when validating a LHT received over sync()
  try {
    const validity: I.validityValue = {
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

  catch (error) {
    console.log('Error verifying join proof')
    console.log(error)
    return(error)
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
    return(error)
  }
}

export async function isValidLeaveProof(data: any[], publicKey: string) {
  // verifies a leave proof received from another node or when validating an LHT received over sync 
  try {
    const validity: I.validityValue = {
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

  catch (error) {
    console.log('Error verifying leave proof')
    console.log(error)
    return(error)
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
    return(error)
  }
}

export async function isValidFailureProof(data: any[], publicKey: string) {
  // PBFT 2/3 vote for now
  // will implement the parsec consensus protocol as a separate module later
  try {
    // called when a failure message is received
    // validates the message and updates the tally in members

  } 

  catch (error) {
    console.log('Error validating failure proof')
    console.log(error)
    return(error)
  }
}

export function encryptAssymetric(value: string, publicKey: string): Promise <string> {
  // encrypt a symmetric key with a private key
  return new Promise <string> ( async (resolve, reject) => {
    try {
      const options: I.encryptionOptions = {
        data: value,
        publicKeys: openpgp.key.readArmored(publicKey).keys
      }
  
      const cipherText: I.encryptedValueObject = await openpgp.encrypt(options)
      const encryptedValue: string = cipherText.data
      resolve(encryptedValue)
    } 
    catch (error) {
      reject(error)
    }
  })
}

export function decryptAssymetric(value: string, privateKeyObject: object): Promise <string> {
  // decrypt a symmetric key with a private key
  return new Promise <string> (async (resolve, reject) => {
    try {
      const options: I.decryptionOptions = {
        message: openpgp.message.readArmored(value),
        privateKeys: [privateKeyObject]
      }
  
      const plainText: I.decrpytedValueObject = await openpgp.decrypt(options)
      const decryptedValue: string = plainText.data
      resolve(decryptedValue)
    } 
    catch (error) {
      reject(error)
    }
  })
}

export function encryptSymmetric(value: string, symkey: string): Promise <string> {
  // encrypts a record value with a symmetric key
  return new Promise <string> (async (resolve, reject) => {
    try {
      const key: Buffer = Buffer.from(symkey, 'hex')
      const byteValue: Uint8Array[] = aesjs.utils.utf8.toBytes(value)
      const aesCtr: any = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5))
      // an insanely compplex object, feel free to add an interface!
      const encryptedBytes: Uint8Array[] = aesCtr.encrypt(byteValue)
      const encryptedHex: string = aesjs.utils.hex.fromBytes(encryptedBytes)
      resolve(encryptedHex)
    } 
    catch (error) {
      reject(error)
    }
  })
}

export function decryptSymmetric(encryptedValue: string, symkey: string): Promise <string> {
  // decrypts a record value with a symmetric key
  return new Promise <string> (async (resolve, reject) => {
    try {
      const key: Buffer = Buffer.from(symkey, 'hex')
      const encryptedBytes: Uint8Array[] = aesjs.utils.hex.toBytes(encryptedValue)
      const aesCtr: any = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5))
      // an insanely compplex object, feel free to add an interface!
      const decryptedBytes: Uint8Array[] = aesCtr.decrypt(encryptedBytes)
      const decryptedText: string = aesjs.utils.utf8.fromBytes(decryptedBytes)
      resolve(decryptedText)
    } 
    catch (error) {
      reject(error)
    }
  })
}




