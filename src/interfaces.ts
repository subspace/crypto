export interface Userid {
  name: string,
  email: string
}

export interface optionsObject {
  userIds: Userid[],
  curve: string,
  passphrase: string
}  

export interface signatureOptions {
  message: string,
  privateKeys: any[],
  detached: boolean
}

export interface signatureValue {
  signature: string
}

export interface verifySignatureOptions {
  message: string,
  signature: string,
  publicKeys: string[]
}

export interface validityValue {
  isValid: boolean,
  reply: {
    type: string,
    data: string
  }
}

export interface encryptionOptions {
  message: string,
  publicKeys: string
}

export interface encryptedValueObject {
  data: string,
  signature: string
}

export interface decryptionOptions {
  message: string,
  privateKeys: any[]
}

export interface decrpytedValueObject {
  data: string
}