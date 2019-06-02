declare type IHashFunction = (input: Uint8Array) => Uint8Array;
export declare class MerkleTree {
    private readonly items;
    private readonly hashFunction;
    constructor(items: Uint8Array[], hashFunction: IHashFunction);
    root(): Uint8Array;
    getProof(item: Uint8Array): Uint8Array;
    static checkProof(root: Uint8Array, item: Uint8Array, proof: Uint8Array, hashFunction: IHashFunction): boolean;
}
export {};
