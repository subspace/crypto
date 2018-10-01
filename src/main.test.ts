import * as crypto from "./main"
import * as interfaces from './interfaces'

const value: string = 'hello subspace'
const falseValue: string = 'herro rubrace'
const hash: string = '00ba5188adff22ee1f8abc61d6e96c371f0d505ec76f90e86d4b0c8748d646bb'
const generateKeys = async () => {
  const options: interfaces.optionsObject = {
    userIds: [{ 
      name: 'me',
      email: 'me@me.com' 
    }],
    curve: "ed25519",
    passphrase: 'some text'
  }
  const key: any = await crypto.generateKeys(options)
  const profile: object = {
    publicKey: key.publicKeyArmored,
    privateKey: key.privateKeyArmored,
    privateKeyObject: await crypto.getPrivateKeyObject(key.privateKeyArmored)
  }
  return profile
}

const keys = generateKeys()



test('getHash', () => {
    expect(crypto.getHash(value)).toBe(hash)
})

// test('getRandom', () => {
//     expect(crypto.getRandom)
//     // 32 bytes long
//     // unique each time 
// })

test('read', () => {
    const buffer: any = Buffer.from(hash, 'hex')
    const readable: string = '00ba5188...'
    expect(crypto.read(buffer)).toBe(readable)
})

test('verifyHash', () => {
    expect(crypto.verifyHash(hash, value)).toBe(true)
    expect(crypto.verifyHash(hash, falseValue)).toBe(false)
})

test('stringify', () => {
  const stringInput: string = 'test'
  const stringOutput: string = 'test'
  expect(crypto.stringify(stringInput)).toBe(stringOutput)

  const arrayInput: any[] = [1, 'abc', 'signature']
  const arrayOutput: string = "1,abc,signature"
  expect(crypto.stringify(arrayInput)).toBe(arrayOutput)

  const objectInput: object = {
    test: 'data',
    some: [1, 2, 3]
  }
  const objectOutput: string = '{"test":"data","some":[1, 2, 3]}'
  expect(crypto.stringify(arrayInput)).toBe(arrayOutput)
})

test('verifyDate', () => {
  const range = 600000
  const testDate: number = Date.now() 
  const validEarly: number = testDate - 599000
  expect(crypto.verifyDate(validEarly, range)).toBe(true)
  const validLate: number = testDate + 599000 
  expect(crypto.verifyDate(validLate, range)).toBe(true)
  const invalidEarly: number = testDate - 601000
  expect(crypto.verifyDate(invalidEarly, range)).toBe(false)
  const invalidLate: number = testDate + 601000
  expect(crypto.verifyDate(invalidLate, range)).toBe(false)
})

// test('generateKeys',() => {
  
// })


