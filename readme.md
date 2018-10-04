# Subspace Crypto Module

A utility library for cryptographic functions

## Usage as a module

Install this module as a dependency into another project

```
$ yarn add 'github:subspace/profile'
```

Require this module inside a script

```typescript
import * as crypto from '@subspace/crypto'

let hash: string = crypto.getHash('abc')

// or

import { getHash } from 'subspace-crypto'

let hash: string = getHash('abc')

```

## API
### crypto.getHash(value: string) : hash: string
Computes the sha256 hash of a string value.

* `value` - any string value, typically stringified JSON

Returns *hash*, a 32 byte hash as a hex encoded string.

### crypto.isValidHash(hash: string, value: string) : valid: boolean
Validates a given hash matches a string value.

* `value` - any string value, typically stringified JSON
* `hash` - 32 byte hash as a hex encoded string

Returns a boolean.

### crypto.getRandom() : random: string
Generates a random 32 byte symmetric encryption key.

Returns *random*, a 32 byte hex encoded string.

### crypto.read(buffer: Buffer) : readeableString: string
Encodes a buffer object (node_id) as a condensed human readable string.

* `buffer` - any hex encoded buffer object

Returns *readableString*, the first 8 characters of the hex encoded string.

### crypto.stringify(value: object | any[]) : value: string
Converts a json object or array into a string.

* `value` - any JSON object or array

Returns *returnValue*, a string encoded value.

### crypto.isDateWithinRange(date: number, range: number) : boolean
Validates a given date is within (+/-) a specified range.

* `date` - a unix timestamp in milliseconds 
* `range` - a range in milliseconds, typically 10 minutes

Returns a boolean.

### async crypto.generateKeys(options: object) : keys: object
Generates and returns a new OpenPGP ED25519 key pair.

* `options` - any string value, typically stringified JSON
  * `userIds` - an array of user objects ``` { name: string, email: string }```
  * `curve` - ECC curve name, defaults to ed25519
  * `passphrase` - an optional passhprahse to protect the private key, defaults to passphrase
 
Returns a *keys* object
* `Key` - the key object
* `privateKeyArmored` - armored private key as a string
* `publicKeyArmored` - armored public key as a string

### async crypto.getPrivateKeyObject(privateKey: string) : privateKeyObject: object
Extracts the private key object from the armored private keys, for encryption and decryption.

* `privateKey` - armored private key

Returns a *privateKeyObject*.

### async crypto.sign(value: string | object | array, privateKeyObject: object) : signature: string
Generates a detached signature of a value given a private key object.

* `value` - a string, object, or array (converts to string)
* `privateKeyObject` - openpgp private key object

Returns a *signature*.

### async crypto.isValidSignature(value: string | object | array, signature: string, publicKey: string) : valid: boolean
Validates a signature matches a given input value for a public key.

* `value` - a string, object, or array (converts to string)
* `signature` - openpgp detached signature
* `publicKey` - openpgp armored public key

Returns a boolean.

### async crypto.createJoineProof(profile: object) : joinProof: any[]
Creates a self-signed join proof for gossip to the host network on network.join().

* `profile` - a subspace profile instance

Returns a join proof array.
* `nodeId` - sha256 hash of public key
* `publicKey` - openpgp armored public key
* `date` - unix timestamp
* `signature` - openpgp detatched signature of above

### async crypto.isValidJoinProof(proof: any[]) : valid: boolean
Validates a join proof has accurate id, signature, and timestamp (10 min range).

* `proof` - a join proof array

Returns a boolean

### async crypto.createLeaveProof(profile: object) : leaveProof: any[]
Creates a self-signed leave proof for gossip to the host network on network.leave().

* `profile` - a subspace profile instance

Returns a leave proof array.
* `nodeId` - sha256 hash of public key
* `date` - unix timestamp
* `signature` - openpgp detatched signature of above

### async crypto.isValidLeaveProof(proof: any[], publicKey: string) : valid: boolean
Validates a leave proof has accurate signature and timestamp (10 min range).

* `proof` - a leave proof array
* `publicKey` - openpgp armored public key (from tracker)

Returns a boolean

### async crypto.createFailureProof(nodeId: string, profile: object) : failureProof: any[]
Creates a self-signed failure proof for broadcast to failed host neighbors on neighbor.failure event.

* `nodeId` - the id for the failed neighbor
* `profile` - a subspace profile instance

Returns a failure proof array.
* `nodeId` - sha256 hash of public key for failed node
* `initiatorId` - sha256 hash of public key for this node
* `publicKey` - openpgp armored public key for this node
* `date` - unix timestamp when failure detected
* `signature` - openpgp detatched signature of above

### async crypto.isValidFailureProof(proof: any[], publicKey: string) : valid: boolean
Validates a failure proof has accurate signature and timestamp (10 min range).

* `proof` - a leave proof array
* `publicKey` - openpgp armored public key (from tracker)

Returns a boolean

### async crypto.encryptAssymetric(value: string, privateKeyObject: object) : encryptedValue: string
Assymetricaly encrypts a string value given a private key object. Used for encryption of symmetric keys.

* `value` - any string value
* `privateKeyObject` - openpgp private key object

Returns an encrypted string value.

### async crypto.decryptSymmetric(encryptedValue: string, privateKeyObject: object) : decryptedValue: string
Assymetricaly decryptes a string value given a private key object. Used for decryption of symmetric keys.

* `value` - any string value
* `privateKeyObject` - openpgp private key object

Returns an decrypted string value.

### async crypto.encryptSymmetric(value: string, symkey: string) : encryptedValue: string
Symmetrically encrypts a string value given a symmetric key using AES-256 cipher.

* `value` - any string value
* `symkey` - 32 bytes string key

Returns an encrypted string value.

### async crypto.decryptSymmetric(encryptedValue: string, symkey: string) : decryptedValue: string
Symmetrically decrypts a string value given a symmetric key using AES-256 cipher.

* `value` - any string value
* `symkey` - 32 bytes string key

Returns an decrypted string value.

### async crypto.getXorDistance(a: [number], b: [number]) : result: Buffer
Measures the XOR distance between two numbers

* `a` - any number
* `b` - any number of the same length

Returns a result as a Buffer.

## Development usage

Clone and install the repo locally   

```
$ git clone https://www.github.com/subspace/crypto.git
$ cd crypto
$ yarn
```

Edit code in src/main.ts

Build manually.  

```
$ tsc -w
```

[Instructions](https://code.visualstudio.com/docs/languages/typescript#_step-2-run-the-typescript-build) to automate with visual studio code.

Run tests with

```
$ npx jest
```
