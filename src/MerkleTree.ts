import {checkProof, getProof, getRoot} from "merkle-tree-binary";

type IHashFunction = (input: Uint8Array) => Uint8Array;

export class MerkleTree {
    constructor(
        private readonly items: Uint8Array[],
        private readonly hashFunction: IHashFunction
    ) {
    }

    public root(): Uint8Array {
        return getRoot(this.items, this.hashFunction);
    }

    public getProof(item: Uint8Array): Uint8Array {
        return getProof(this.items, item, this.hashFunction)
    }

    public static checkProof(root: Uint8Array, item: Uint8Array, proof: Uint8Array, hashFunction: IHashFunction): boolean {
        return checkProof(root, proof, item, hashFunction);
    }
}
