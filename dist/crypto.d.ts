/// <reference types="node" />
import * as interfaces from './interfaces';
export { jumpConsistentHash } from '@subspace/jump-consistent-hash';
export { Destination as rendezvousHashDestination, pickDestinations as rendezvousHashPickDestinations } from '@subspace/rendezvous-hash';
export declare function getHash(value: string): string;
export declare function getHash64(value: string): Buffer;
export declare function isValidHash(hash: string, value: string): boolean;
export declare function getRandom(): string;
export declare function read(buffer: Buffer): string;
export declare function stringify(value: string | object | any[]): string;
export declare function isDateWithinRange(date: number, range: number): boolean;
export declare function generateKeys(name: string, email: string, passphrase: string): Promise<any>;
export declare function getPrivateKeyObject(privateKey: string, passphrase: string): Promise<any>;
export declare function sign(value: string | object | any[], privateKeyObject: any): Promise<string>;
export declare function isValidSignature(value: string | object | any[], signature: string, publicKey: string): Promise<boolean>;
<<<<<<< HEAD
export declare function createProofOfSpace(seed: string, size: number): {
    id: string;
    createdAt: number;
    size: number;
    seed: string;
    plot: Set<string>;
};
export declare function isValidProofOfSpace(key: string, size: number, proofId: string): boolean;
export declare function createProofOfTime(seed: string): number;
export declare function isValidProofOfTime(seed: string, time: number): boolean;
=======
export declare function isValidMessageSignature(message: any): Promise<boolean>;
>>>>>>> master
export declare function createJoinProof(profile: any): Promise<any[]>;
export declare function isValidJoinProof(data: any[]): Promise<interfaces.validityValue>;
export declare function createLeaveProof(profile: any): Promise<any[]>;
export declare function isValidLeaveProof(data: any[], publicKey: string): Promise<interfaces.validityValue>;
export declare function createFailureProof(peerId: string, profile: any): Promise<void>;
export declare function isValidFailureProof(data: any[], publicKey: string): Promise<void>;
export declare function encryptAssymetric(value: string, publicKey: string): Promise<string>;
export declare function decryptAssymetric(value: string, privateKeyObject: object): Promise<string>;
export declare function encryptSymmetric(value: string, symkey: string): any;
export declare function decryptSymmetric(encryptedValue: string, symkey: string): string;
