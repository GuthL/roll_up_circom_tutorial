# roll_up tutorial

## Introduction

roll_up is a name for the pattern of performing merkle tree updates, signature validations inside a succinct proof system. This allows us to make dapps with thorughput of between 100tps and 37000 tps on ethereum today. 

This has a transformative scaleing implications. We can do 500 tps* and still maintain data availability guarrenetees of ethereum. We end up including with our snark a diff between state t and state t+1 as well as a proof that the transition from t to t+1 is correct.

In a bunch of contexts we don't need to have all this data available. For example we could build a non-custodial exchange where the exchange operator is able to deprive me of access to my funds. This is a strick improvement over centralized exchanges. There are a bunch of less critical applications that can enter this modle and simply do a redeployment if this attack happens. For example crypto kities, on chain twitter would be good candidates for this kind of approch.

If we remove the need to have data availability on chain we will be able to reach 8000 tps. If we weaken our assumitions further and stake the operator and slash them if they ever publish a proof that is invalid we can reduce the gas costs from 500k gas to the gas cost of putting a snark proof in storage. 288 bytes of storage space. 640k gas per kilo byte. So that means we can approach 34000 tps if we don't validate snarks or put data on chain. We only need to validate them if they are incorrect and then we can slash the operator. 

The tools to build with snarks are improving to the point where you can make a mixer in a 3 day hackathon. You can also make roll_up style dapps. 
Here we introduce you to the tools that circom provides. It gives a nice dev experince but still needs some work on the proving time optimizations. But it should be enough to play around with and if you want to go to prod at the hackathon we include some ideas about doing this in the disclaimer section. 

* Note we ignore the cost of createing the snark proof and assume the operator is able to bear these costs. Which is less 100 USD per proof and is sub cent per transaction. This cost only needs to be paid by a single participant. 

## Operator paradym

We have a new paradym where users create signatures and an operator create snarks that aggragate these signatures together and perform state transitions based upon the rules defined in the snark.

The state of the system is defined by a merkle root.

A snark takes the previous merkel root as an input performs some state transition defined by the snark and produces a new merkle root as the output. Our smart contract tracks this merkle root. 

Inside our snark we define the rules of our state transition. It defines what state transitions are legal and illegal. 

## Signature validation

We put a public key in our merkle tree and proof we have a signature that was created by that public key for a message of size 80 bits. Save the following snippet under eddsa_mimc_verifier.circom
```
include "./circuits/eddsamimc.circom";

component main = EdDSAMiMCVerifier();
```
To generate the circuit usable by snarkjs, run:
```
circom eddsa_mimc_verifier.circom -o eddsa_mimc_verifier.cir
```

From circomlib, you can use eddsa.js to generate an input. Copy the following snippet Copy into a file named input.json.
```
const eddsa = require("./src/eddsa.js");
const snarkjs = require("snarkjs");
const fs = require('fs');
var util = require('util');

const bigInt = snarkjs.bigInt;

const msg = bigInt(9999);

const prvKey = Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", "hex");

const pubKey = eddsa.prv2pub(prvKey);

const signature = eddsa.signMiMC(prvKey, msg);

const inputs = {
            enabled: 1,
            Ax: pubKey[0].toString(),
            Ay: pubKey[1].toString(),
            R8x: signature.R8[0].toString(),
            R8y: signature.R8[1].toString(),
            S: signature.S.toString(),
            M: msg.toString()}

fs.writeFileSync('./input.json', JSON.stringify(inputs) , 'utf-8');
```

Then test your circuit by running the following command:
```
snarkjs calculatewitness -c eddsa_mimc_verifier.cir
```



## Permissioned markle tree update

So now lets say we want to update the leaf in the merkle tree 
but the only let people update the leaf is if they have the current public key. 

*Wait this is an NFT :D where the index in the tree is the token owner.*

Save the following snippet under leaf_update.circom

```
include "./circuits/mimc.circom";
include "./circuits/eddsamimc.circom";
include "./circuits/bitify.circom";

template Main(n) {
    signal private input paths_to_root[n-1];

    signal input current_state;
    signal input pubkey_x;
    signal input pubkey_y;
    signal input R8x;
    signal input R8y;
    signal input S;
    signal input nonce;

    signal output out;

    var i;
    
    component old_hash = MultiMiMC7(3,91);
    old_hash.in[0] <== pubkey_x;
    old_hash.in[1] <== pubkey_y;
    old_hash.in[2] <== nonce;
    
    component old_merkle[n-1];
    old_merkle[0] = MultiMiMC7(2,91);
    old_merkle[0].in[0] <== old_hash.out;
    old_merkle[0].in[1] <== paths_to_root[0];
    for (i=1; i<n-1; i++){
        old_merkle[i] = MultiMiMC7(2,91);
        old_merkle[i].in[0] <== old_merkle[i-1].out;
        old_merkle[i].in[1] <== paths_to_root[i-1];
    }

    current_state === old_merkle[n-2].out;

    component verifier = EdDSAMiMCVerifier();   
    verifier.enabled <== 1;
    verifier.Ax <== pubkey_x;
    verifier.Ay <== pubkey_y;
    verifier.R8x <== R8x
    verifier.R8y <== R8y
    verifier.S <== S;
    verifier.M <== old_hash.out;
    
    component new_hash = MultiMiMC7(3,91);
    new_hash.in[0] <== pubkey_x;
    new_hash.in[1] <== pubkey_y;
    new_hash.in[2] <== nonce+1;
    
    component new_merkle[n-1];
    new_merkle[0] = MultiMiMC7(2,91);
    new_merkle[0].in[0] <== new_hash.out;
    new_merkle[0].in[1] <== paths_to_root[0];
    for (i=1; i<n-1; i++){
        new_merkle[i] = MultiMiMC7(2,91);
        new_merkle[i].in[0] <== new_merkle[i-1].out;
        new_merkle[i].in[1] <== paths_to_root[i-1];
    }
    
    out <== new_merkle[n-2].out;
}

component main = Main(24);
```

To generate the circuit usable by snarkjs, run:
```
circom leaf_update.circom -o leaf_update.cir
```
Copy the following snippet and generate an example into a file named input.json.

```
const eddsa = require("./src/eddsa.js");
const snarkjs = require("snarkjs");
const fs = require('fs');
const util = require('util');
const mimcjs = require("./src/mimc7.js");

const bigInt = snarkjs.bigInt;

const DEPTH = 24;
const msg = bigInt(9999);

const prvKey = Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", "hex");

const pubKey = eddsa.prv2pub(prvKey);
const nonce = 0;
const old_hash = mimcjs.multiHash([pubKey[0],pubKey[1],nonce]);

var old_merkle = new Array(DEPTH-1);
old_merkle[0] = mimcjs.multiHash([old_hash,0]);
var i;
for (i = 1; i < DEPTH-1; i++) { 
  old_merkle[i] = mimcjs.multiHash([old_merkle[i-1],0]);
}
console.log("Old Root")
console.log(old_merkle[DEPTH-2]);

const signature = eddsa.signMiMC(prvKey, old_hash);

const inputs = {
			current_state: old_merkle[DEPTH-2].toString(),
			paths_to_root: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            pubkey_x: pubKey[0].toString(),
            pubkey_y: pubKey[1].toString(),
            R8x: signature.R8[0].toString(),
            R8y: signature.R8[1].toString(),
            S: signature.S.toString(),
        	nonce: 0}

 console.log(inputs)

fs.writeFileSync('./input.json', JSON.stringify(inputs) , 'utf-8');

const new_hash = mimcjs.multiHash([pubKey[0],pubKey[1],nonce+1]);

var new_merkle = new Array(DEPTH-1);
new_merkle[0] = mimcjs.multiHash([new_hash,0]);
var i;
for (i = 1; i < DEPTH-1; i++) { 
  new_merkle[i] = mimcjs.multiHash([new_merkle[i-1],0]);
}
console.log("New Root")
console.log(new_merkle[DEPTH-2]);
```

## Token transfers

Lets change our leaf so that instead of a public key it holds a public key and a number. 
We can use the number to represent a token balance. 

```
include "./circuits/mimc.circom";
include "./circuits/eddsamimc.circom";
include "./circuits/bitify.circom";

template Main(n) {
    signal input current_state;

    signal private input paths2old_root_from[n-1];
    signal private input paths2old_root_to[n-1];
    signal private input paths2new_root_from[n-1];
    signal private input paths2new_root_to[n-1];

    signal private input paths2root_from_pos[n-1];
    signal private input paths2root_to_pos[n-1];
    
    signal private input pubkey_x;
    signal private input pubkey_y;
    signal private input R8x;
    signal private input R8y;
    signal private input S;

    signal private input nonce_from;
    signal private input to;
    signal private input nonce_to;
    signal private input amount;

    signal private input token_balance_from;
    signal private input token_balance_to;
    signal private input token_type_from;
    signal private input token_type_to;

    signal output out;

    var i;

    var NONCE_MAX_VALUE = 100;
    
    // accounts existence check
    component old_hash_from = MultiMiMC7(4,91);
    old_hash_from.in[0] <== pubkey_x;
    old_hash_from.in[1] <== token_balance_from;
    old_hash_from.in[2] <== nonce_from;
    old_hash_from.in[3] <== token_type_from;

    component old_merkle_from[n-1];
    old_merkle_from[0] = MultiMiMC7(2,91);
    old_merkle_from[0].in[0] <== old_hash_from.out - paths2root_from_pos[0]* (old_hash_from.out - paths2old_root_from[0]);
    old_merkle_from[0].in[1] <== paths2old_root_from[0] - paths2root_from_pos[0]* (paths2old_root_from[0] - old_hash_from.out);
    
    for (i=1; i<n-1; i++){
    	old_merkle_from[i] = MultiMiMC7(2,91);
    	old_merkle_from[i].in[0] <== old_merkle_from[i-1].out - paths2root_from_pos[i]* (old_merkle_from[i-1].out - paths2old_root_from[i]);
    	old_merkle_from[i].in[1] <== paths2old_root_from[i] - paths2root_from_pos[i]* (paths2old_root_from[i] - old_merkle_from[i-1].out);
    	}

    current_state === old_merkle_from[n-2].out;

    component old_hash_to = MultiMiMC7(4,91);
    old_hash_to.in[0] <== to;
    old_hash_to.in[1] <== token_balance_to;
    old_hash_to.in[2] <== nonce_to;
    old_hash_to.in[3] <== token_type_to;

    component old_merkle_to[n-1];
    old_merkle_to[0] = MultiMiMC7(2,91);
    old_merkle_to[0].in[0] <== old_hash_to.out - paths2root_to_pos[0]* (old_hash_to.out - paths2old_root_to[0]);
    old_merkle_to[0].in[1] <== paths2old_root_to[0] - paths2root_to_pos[0]* (paths2old_root_to[0] - old_hash_to.out);
    
    for (i=1; i<n-1; i++){
    	old_merkle_to[i] = MultiMiMC7(2,91);
    	old_merkle_to[i].in[0] <== old_merkle_to[i-1].out - paths2root_to_pos[i]* (old_merkle_to[i-1].out - paths2old_root_to[i]);
    	old_merkle_to[i].in[1] <== paths2old_root_to[i] - paths2root_to_pos[i]* (paths2old_root_to[i] - old_merkle_to[i-1].out);
    	}

    current_state === old_merkle_to[n-2].out;

// authorization check
    component verifier = EdDSAMiMCVerifier();   
    verifier.enabled <== 1;
    verifier.Ax <== pubkey_x;
    verifier.Ay <== pubkey_y;
    verifier.R8x <== R8x
    verifier.R8y <== R8y
    verifier.S <== S;
    verifier.M <== old_hash_from.out;
    
    // balance checks
    token_balance_from-amount <= token_balance_from;
    token_balance_to + amount >= token_balance_to;

    nonce_from != NONCE_MAX_VALUE;
    token_type_from === token_type_to;

    // accounts updates
    component new_hash_from = MultiMiMC7(4,91);
    new_hash_from.in[0] <== pubkey_x;
    new_hash_from.in[1] <== token_balance_from-amount;
    new_hash_from.in[2] <== nonce_from+1;
    new_hash_from.in[3] <== token_type_from;
    
	component new_merkle_from[n-1];
    new_merkle_from[0] = MultiMiMC7(2,91);
    new_merkle_from[0].in[0] <== new_hash_from.out - paths2root_from_pos[0]* (new_hash_from.out - paths2new_root_from[0]);
    new_merkle_from[0].in[1] <== paths2new_root_from[0] - paths2root_from_pos[0]* (paths2new_root_from[0] - new_hash_from.out);
    
    for (i=1; i<n-1; i++){
    	new_merkle_from[i] = MultiMiMC7(2,91);
    	new_merkle_from[i].in[0] <== new_merkle_from[i-1].out - paths2root_from_pos[i]* (new_merkle_from[i-1].out - paths2new_root_from[i]);
    	new_merkle_from[i].in[1] <== paths2new_root_from[i] - paths2root_from_pos[i]* (paths2new_root_from[i] - new_merkle_from[i-1].out);
    	}

    component new_hash_to = MultiMiMC7(4,91);
    new_hash_to.in[0] <== to;
    new_hash_to.in[1] <== token_balance_to+amount;
    new_hash_to.in[2] <== nonce_to;
    new_hash_to.in[3] <== token_type_to;

	component new_merkle_to[n-1];
    new_merkle_to[0] = MultiMiMC7(2,91);
    new_merkle_to[0].in[0] <== new_hash_to.out - paths2root_to_pos[0]* (new_hash_to.out - paths2new_root_to[0]);
    new_merkle_to[0].in[1] <== paths2new_root_to[0] - paths2root_to_pos[0]* (paths2new_root_to[0] - new_hash_to.out);
    
    for (i=1; i<n-1; i++){
    	new_merkle_to[i] = MultiMiMC7(2,91);
    	new_merkle_to[i].in[0] <== new_merkle_to[i-1].out - paths2root_to_pos[i]* (new_merkle_to[i-1].out - paths2new_root_to[i]);
    	new_merkle_to[i].in[1] <== paths2new_root_to[i] - paths2root_to_pos[i]* (paths2new_root_to[i] - new_merkle_to[i-1].out);
    	}

   	new_merkle_from[n-2].out === new_merkle_to[n-2].out
    
    out <== new_merkle_to[n-2].out;

    }

component main = Main(6);

```
To generate the circuit usable by snarkjs, run:
```
circom tokens_transfer.circom -o tokens_transfer.cir
```
Copy the following snippet and generate an example into a file named input.json.

```
const eddsa = require("./src/eddsa.js");
const snarkjs = require("snarkjs");
const fs = require('fs');
const util = require('util');
const mimcjs = require("./src/mimc7.js");

const bigInt = snarkjs.bigInt;

const DEPTH = 6;

const prvKey_from = Buffer.from("0000000000000000000000000000000000000000000000000000000000000001", "hex");
const prvKey_to = Buffer.from("0000000000000000000000000000000000000000000000000000000000000002", "hex");

const pubKey_from = eddsa.prv2pub(prvKey_from);
const pubKey_to = eddsa.prv2pub(prvKey_to);

const nonce_from = 0;
const nonce_to = 0;

const token_type_from = 10;
const token_balance_from = 1000;
const token_type_to = 10;
const token_balance_to = 2000;
const amount = 100;

const old_hash_leaf_from = mimcjs.multiHash([pubKey_from[0], token_balance_from, nonce_from, token_type_from]);
const old_hash_leaf_to = mimcjs.multiHash([pubKey_to[0], token_balance_to, nonce_to, token_type_to]);

console.log("We selected to place account 1 and 2 at index 0 and 1 of the Merkle Tree");
var old_merkle = new Array(DEPTH-1);
old_merkle[0] = mimcjs.multiHash([old_hash_leaf_from,old_hash_leaf_to]);

var i;
for (i = 1; i < DEPTH-1; i++) { 
  old_merkle[i] = mimcjs.multiHash([old_merkle[i-1],0]);
}

console.log("Initial Root")
console.log(old_merkle[DEPTH-2]);

const signature = eddsa.signMiMC(prvKey_from, old_hash_leaf_from);

const new_hash_leaf_from = mimcjs.multiHash([pubKey_from[0], token_balance_from-amount, nonce_from+1, token_type_from]);
const new_hash_leaf_to = mimcjs.multiHash([pubKey_to[0], token_balance_to+amount, nonce_to, token_type_to]);

var new_merkle = new Array(DEPTH-1);
new_merkle[0] = mimcjs.multiHash([new_hash_leaf_from,new_hash_leaf_to]);
var i;
for (i = 1; i < DEPTH-1; i++) { 
  new_merkle[i] = mimcjs.multiHash([new_merkle[i-1],0]);
}

console.log("Updated Root")
console.log(new_merkle[DEPTH-2]);

const inputs = {
			paths2old_root_from: [old_hash_leaf_to.toString(), 0, 0, 0, 0],
			paths2old_root_to: [old_hash_leaf_from.toString(), 0, 0, 0, 0],
			paths2new_root_from: [new_hash_leaf_to.toString(), 0, 0, 0, 0],
			paths2new_root_to: [new_hash_leaf_from.toString(), 0, 0, 0, 0],
			paths2root_from_pos: [0, 0, 0, 0, 0],
			paths2root_to_pos: [1, 0, 0, 0, 0],
			
			current_state: old_merkle[DEPTH-2].toString(),
            pubkey_x: pubKey_from[0].toString(),
            pubkey_y: pubKey_from[1].toString(),
            R8x: signature.R8[0].toString(),
            R8y: signature.R8[1].toString(),
            S: signature.S.toString(),
        	nonce_from: nonce_from.toString(),
        	to: pubKey_to[0].toString(),
        	nonce_to: nonce_to.toString(),
        	amount: amount.toString(),
        	token_balance_from:token_balance_from.toString(),
        	token_balance_to: token_balance_to.toString(),
        	token_type_from:token_type_from.toString(),
        	token_type_to:token_type_to.toString()
        }

fs.writeFileSync('./input.json', JSON.stringify(inputs) , 'utf-8');

```
Careful, this circuit is quite big and took to setup on my MacbookPro more than 10m.
The witness is generally a better way to check if your circuit compiles properly.

And we need to add some token balance requirements as follows

## Deposits 

If we have time

### Withdraws 

If we have time

## Prover race conditions

The prover takes x seconds to create a proof. Therefore we need the merkle root to be the same at the end of the proof as at the start. 

So we need to stagger the depsoits and withdraws that change the token balances. 


## Homework :P

We need to add deposits and withdraws to the tutorial

Instead of just storing the public key in the leaf we can store arbitrary information. Can you build

1. NFT
2. tweets on chain, 
3. votes
4. Staked tokens 

anything you can store in the EVM you can store here. 

## Disclaimer

1. Circom is not really fast enough to nativley create proofs and trusted setups for merkle trees deeper than 12 hashes. or 2 trnasactions per block so we increase things
2. This does not undermine the central claim here that we can do 500 tps on ethereum for a large subset of dapp logics. The reason being that we can use circom as a user frindly developer enviroment and pass all the proving and setup requiremntes to bellman which is much faster. 
3. Even then bellman takes ~15 mintues to create a proof of AWS 40 core server. We can produce proofs in parallel that costs about 100 usd per proof. This is still sub sent per transaction which is really cheap compared to eth. 