export interface validityValue {
    isValid: boolean;
    reply: {
        type: string;
        data: string;
    };
}
export interface encryptionOptions {
    message: string;
    publicKeys: string;
}
export interface encryptedValueObject {
    data: string;
    signature: string;
}
export interface decryptionOptions {
    message: string;
    privateKeys: any[];
}
export interface decrpytedValueObject {
    data: string;
}
