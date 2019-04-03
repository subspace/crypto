export interface validityValue {
  isValid: boolean,
  reply: {
    type: string,
    data: string
  }
}

export interface encryptionOptions {
  message: any,
  publicKeys: any[]
}

export interface encryptedValueObject {
  data: string,
  signature: string
}

export interface decryptionOptions {
  message: any,
  privateKeys: any[]
}

export interface decrpytedValueObject {
  data: string
}
