(function (factory) {
    if (typeof module === "object" && typeof module.exports === "object") {
        var v = factory(require, exports);
        if (v !== undefined) module.exports = v;
    }
    else if (typeof define === "function" && define.amd) {
        define(["require", "exports", "merkle-tree-binary"], factory);
    }
})(function (require, exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    const merkle_tree_binary_1 = require("merkle-tree-binary");
    class MerkleTree {
        constructor(items, hashFunction) {
            this.items = items;
            this.hashFunction = hashFunction;
        }
        root() {
            return merkle_tree_binary_1.getRoot(this.items, this.hashFunction);
        }
        getProof(item) {
            return merkle_tree_binary_1.getProof(this.items, item, this.hashFunction);
        }
        static checkProof(root, item, proof, hashFunction) {
            return merkle_tree_binary_1.checkProof(root, proof, item, hashFunction);
        }
    }
    exports.MerkleTree = MerkleTree;
});
//# sourceMappingURL=MerkleTree.js.map