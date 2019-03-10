# Roll\_up tutorial, a layer 1 SNARK-based scalability solution for Ethereum

## Introduction

roll\_up is a name for the pattern of performing merkle tree updates, signature validations inside a succinct proof system. This allows us to make dapps with throughput of between 100tps and 37000 tps on ethereum today. 

This has a transformative scaling implications. We can do 500 tps\* and still maintain data availability guarantees of Ethereum. We end up including with our snark a diff between state t and state t+1 as well as a proof that the transition from t to t+1 is correct.

![](https://i.imgur.com/E5oDG1a.png)

### Data availability options
In a bunch of contexts we don't need to have all this data available. For example, we could build a non-custodial exchange where the exchange operator is able to deprive me of access to my funds, which would still be a strict improvement over centralized exchanges. There are a bunch of less critical applications that can enter this model and simply do a redeployment if this attack happens. For example crypto kitties, on-chain twitter would be good candidates for this kind of approach.

If we remove the need to have data availability on chain, we will be able to reach 8000 tps. If we weaken our assumptions further and stake the operator and slash them if they ever publish a proof that is invalid, we can reduce the gas costs from 500k gas to the gas cost of putting a snark proof in storage. 288 bytes of storage space. 640k gas per kilo byte. So that means we can approach 34000 tps if we don't validate snarks or put data on chain. We only need to validate them if they are incorrect and then we can slash the operator. 

The tools to build with snarks are improving to the point where you can make a mixer in a 3 day hackathon. You can also make roll_up style dapps. 
Here we introduce you to the tools that circom provides. It gives a nice dev experience but still needs some work on the proving time optimizations. But it should be enough to play around with and if you want to go to prod at the hackathon we include some ideas about doing this in the disclaimer section. 

\* Note we ignore the cost of creating the snark proof and assume the operator is able to bear these costs. Which is less 100 USD per proof and is sub cent per transaction. This cost only needs to be paid by a single participant. 

## Operator paradigm

We have a new paradigm where users create signatures and an operator create snarks that aggregate these signatures together and perform state transitions based upon the rules defined in the snark.

The state of the system is defined by a merkle root.

A snark takes the previous merkle root as an input performs some state transition defined by the snark and produces a new merkle root as the output. Our smart contract tracks this merkle root. 

Inside our snark we define the rules of our state transition. It defines what state transitions are legal and illegal. 

## Pre-requirements

Check out this circom intro https://github.com/iden3/circom/blob/master/TUTORIAL.md

```
npm install -g circom
npm install -g snarkjs
git clone https://github.com/iden3/circomlib
git clone https://github.com/GuthL/roll_up_circom_tutorial

```
Move the scripts from this repository (roll_up_circom_tutorial/leaf_update, roll_up_circom_tutorial/signature_verification, roll_up_circom_tutorial/tokens_transfer) to the root of circomlib project.

## Signature validation

We put a public key in our merkle tree and prove we have a signature that was created by that public key for a message of size 80 bits. In the root of the circomlib project, save the following snippet under eddsa_mimc_verifier.circom
```
include "./circuits/eddsamimc.circom";

component main = EdDSAMiMCVerifier();
```
To generate the circuit usable by snarkjs, run:
```
circom eddsa_mimc_verifier.circom -o eddsa_mimc_verifier.cir
```

From circomlib, you can use eddsa.js to generate an input. Copy the following snippet into a file named input.js. Then, run `node input.js` to generate the input.json which snarkjs recognises.

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

## Permissioned merkle tree update

So now lets say we want to update the leaf in the merkle tree 
but the only let people update the leaf is if they have the current public key. The leaf index in the tree represents an NFT token owned a user.

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
Once again, copy the following snippet and generate an example into a file named input.json.

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

### Putting this all inside a smart contract 

Compile the code
```
circom tokens_transfer.circom -o circuit.json
```

Perform the trusted setup *this will take a long time ~ 20 mins* see the comments about reducing proving time in the disclaimer. 
They apply here also. 

```
snarkjs setup --protocol groth
```

Create a smart contract to verify this circuit.

```
snarkjs generateverifier
```

We can take the result of the previous command and use it to build our side chain

```
solidity ^0.4.17;

import "./verifier.sol";

contract sidechain is Verifier {
    uint256 merkle_root;
    address operator;
    
    function snarkTransition (
            uint[2] a,
            uint[2][2] b,
            uint[2] c,
            uint[2] input) internal {
        //make sure only the operator can update the merkle tree
        require(msg.sender == operator);
        //validate proof
        require(verifyProof(a,b,c,input));
        // update merkle root
        merkle_root = input[0];
        // Do Deposits
        // Do Withdraws
    }
    
    function deposit() internal {
        
    }
    
    function withdraw() internal {
        
    }
    
    function leaf_insert() internal {
        
    }
    
    function mimic () internal {
        
    }
} 
```

So now we have a smart contract where we can deposit coins to move to the side chain. 

Then we can transfer them via snark and eventually we can withdraw them to the main chain again. 

So next lets work out how the deposit will work. 

## Deposits 

Firstly we need to deploy the mimc hash contract like 
The circom team have provided a assembly version so they can reduce gas costs. 

Its non trivial to deploy bytecode (I think) directly from remix so I have a python script to deploye it 
```
import json
import web3
import pdb

from web3 import Web3, HTTPProvider, TestRPCProvider
from solc import compile_source, compile_standard, compile_files
from solc import compile_source, compile_files, link_code
from web3.contract import ConciseContract


w3 = Web3(HTTPProvider("http://localhost:8545"));


  

def contract_deploy():
    miximus_interface = {}
    test = json.loads('{"asdf":12}')
    miximus_interface['abi'] = [{ "constant": True, "inputs": [             {                 "name": "in_x",                 "type": "uint256"             },             {                 "name": "in_k",                 "type": "uint256"             }         ],         "name": "MiMCpe7",         "outputs": [             {                 "name": "out_x",                 "type": "uint256"             }         ],         "payable": False,         "stateMutability": "pure",         "type": "function"     } ]
    

    miximus_interface['bin'] = "0x38600c6000396112636000f3604460006000377c01000000000000000000000000000000000000000000000000000000006000510463d15ca109146200003557fe5b7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001602451818060045183088180828009818180090909828080927f8ef758973a8cabb7492f4d05f39a1b93dc29a57c0104feffb67c57dfc70a98e70883088180828009818180090909828080927f82885e3a7813b2259da69bc36657e8bc48c092832474ec6eb0de5dc54281d34b0883088180828009818180090909828080927fa399e58dcea3077e6d1c08044780913ff598f4d83a1494638c89c8495edb4adb0883088180828009818180090909828080927f63d273ec3d199e351a406dac488fbc7e41f42a4757a1d5ad842b8a195cb6928e0883088180828009818180090909828080927f7a14e37902fca6e97c891080d2e5da42118dc7a48c1a6406d137e6b2d4798bda0883088180828009818180090909828080927fc7398333d08c0d67b82b09f3bae043e25241145ddcf4f41e886bf359675a631d0883088180828009818180090909828080927f49219c213265f3b58b4952f83d333b8ddadc10b41e5a0b5b839dd28d22534be60883088180828009818180090909828080927ff92c4e4b3997f23536d9a245812da66d75ac291d3ea970553e280f33fb5607ff0883088180828009818180090909828080927f560ae58d7e5dbe13abc47d4410e2a1884407acadfe79e738b025b9610a7475130883088180828009818180090909828080927f9b605f2a033bbd5f4ae9034a44b14b10274188a04778f0fd4d5382791b50f5710883088180828009818180090909828080927fed013c59b0bb60afc36ff4919346f24bdcf83ee82b4101a9f0e76220ac02c6760883088180828009818180090909828080927f6bed8c2bdcd52f2cae73f1a1329f55a90bdc6d1b4dd338ea899923efa0666ba60883088180828009818180090909828080927f05d1e0ac576d1ec814b621516339ae1a291c7df36b5fd6cf0b4e3c9cd25e30720883088180828009818180090909828080927fb849e751322c2535825f4f50ecf9d117d5aa1adaad3cfde9b5005d9e090bc5120883088180828009818180090909828080927f196309f1d170d741ab1ce90c39772017fb7cdec78c37882b98a6b56956c13def0883088180828009818180090909828080927fa3a8fc6f690aa0b9a85e54650210244f8194e7bad650f6f46064ea02f1e9e4f80883088180828009818180090909828080927f7cc814ea4149bd8c15f067c1129cdc5acfcb192bc0a92381a2a5fbd4129826f70883088180828009818180090909828080927ff8bd64ba20de36cd8b1acbbc153e92fdcedfa80c28b281740a67246a22c53e9f0883088180828009818180090909828080927fd470b297263c701dbd3de0a18b97cd28356a290e5c19a49aa9af7c9b51cebba90883088180828009818180090909828080927f2bd4cdc962e3da62cb3c96f7c428a9b0d518bfa7ce26f8fce7a6af769afb65400883088180828009818180090909828080927fb61abedd23809ec1edbd0a25cb6740b2c098ba799dfd1ebf1b756078ecabfe5b0883088180828009818180090909828080927fde719f9e471c9c5c5525e61c5fd912258aba6c665e378870875892ae0e3c7d190883088180828009818180090909828080927f18053e9f0d45f9eefbda135bfd39329e34837e633565c314fb9030b9db7381bb0883088180828009818180090909828080927fa75ce5dfe5a86c3b7a5239e30b7081c925ba442cc7f0a75b9b61037d0f9c5aa10883088180828009818180090909828080927ff99472814762e714c63982b48395476c9c9cf3b208a071801edd5170542b715e0883088180828009818180090909828080927f3aadfd9e9f435085887aaf5afc9d05b849a428c353da84c04ac6d69dce88a1b70883088180828009818180090909828080927f43279d5e9bd83cf67bb96f9f76283c649a153c47f14dae36a031bdf4437b733b0883088180828009818180090909828080927ff2836dead1465663cf48597615479fb608d63867e759f63111c167705ce5dbcd0883088180828009818180090909828080927ff69c71c71b05b227ce508f275fb711d1afa8da62f91d786e12519f177d24a86a0883088180828009818180090909828080927fb53e118c3601dcdd51eb0121238d1435ccc45981ea9d69e939ee96904044921a0883088180828009818180090909828080927f0d56329982f3df38a3f19fb814c3013f419ba0eb8403b27c0c0e75c6fe1cf4680883088180828009818180090909828080927fe093294bfb03169c1d84583e4f42f7e84fbeca2dd88fdbdce5ff8ba779692e8e0883088180828009818180090909828080927f40c0a0cad932f2a819007bd28188b3b7a206c4b09b9211b6d172646843c7e7bf0883088180828009818180090909828080927f64a3ed3fce960bb53aaa1ef6c51abed6d3ea50451112cea7604b520724c6307b0883088180828009818180090909828080927f42c735abd4bf56f155751f28f4159a7a018ee26d6e297ca4678d7957906ace330883088180828009818180090909828080927f0ee68c3e38c194033994c0d4d7bde35bfafa35b22a95f915f82c5a3b0422bd9a0883088180828009818180090909828080927f8faddf61946f884c4391360b671ca84cbb24a62743f70a4d6d11c2a7e77e69040883088180828009818180090909828080927f4eb87ba4b3d521a2e65ad7f845e381ff580d206cbd9d943227fbc692a58656b00883088180828009818180090909828080927f3c07ed74275c56d187b25f08f6b12641aeabc03ba7adef25528eea293c5ef6330883088180828009818180090909828080927feb5144d110de00a827fed745247960d1b0c4df1b566a25c69b8d4920dfcaf88f0883088180828009818180090909828080927f9c8eebe1fef58743a240a03faf9f1ee7b30cf569c7b7f3a4fd0555bdce1a50bb0883088180828009818180090909828080927fbcf3250a5bf2539c8bc39817165852a5b1c8703849e9adffdb4e932902d68a150883088180828009818180090909828080927f5aee420145726e8dc9774a21e95a3e731978ec1fa7302fcdb41bf765363a84460883088180828009818180090909828080927fa87dd94092802f5aa12987a330f12e21cca117c81a3d384f0613ffc33ca8786b0883088180828009818180090909828080927f6cf601ee0e4e12fab3b1e75235a0051322ffd29912e27ecec929af4e31f9be2d0883088180828009818180090909828080927fe9c177f908149788df74e085786f9fea7ddd4ebde587667776a1746ee43993ff0883088180828009818180090909828080927fece861dd4efb6af7f2121e4cead434d78cbf78ef04fe46fc797119a8d4efc5e90883088180828009818180090909828080927fa87f07fe1d34c367abb74d2e118c6ccd675ca874dd6a6b119fa897bc5b53f6b70883088180828009818180090909828080927fc5991f171b6c36e341e0ba5381279de873304487943e749da12d3c5232096bd90883088180828009818180090909828080927f7b056e3b729fbd873d22ae369a44fc7b90d1b37eb2be6bc7ec8dd0ab0bdace930883088180828009818180090909828080927f296255b5e697e517c502ba49b18aaad89514a490a02e7a878b5d559841b93fbd0883088180828009818180090909828080927fd8d96f4b9ee595cc96032f2dbf6b26792bc4070bde83ac1676d09cc913da79ab0883088180828009818180090909828080927f5daf4d4a883a85c0e6d51d1caab084e144916db90fc9e566deb5eab28369a5980883088180828009818180090909828080927f4c72feda25fb2697df6d185100994f868d2ea2854a4229efb7bec43182c79ba70883088180828009818180090909828080927fb79d49d6f2b88854af9de8aa37d7ac1030be22a122b708c14739d4d255d34d480883088180828009818180090909828080927f04e674d88b90b1188353106ae25c0447acace9dc6d62cfe7fec2d7993dfd7a220883088180828009818180090909828080927f9f201eb644d4d4ec8dfa30bae199819d9cb6a5a960bc2b6f74cc25b4669d7e0c0883088180828009818180090909828080927f5e64449e73b48c2f6a4a89fe1beff64911e04b608d8c219f889bd69209e4d4ef0883088180828009818180090909828080927f395130bbdf4e81f728a6df6c4e8921ee145b5a64251326e8fef583dc6ee6694e0883088180828009818180090909828080927f8ce35503786afaca4c97aab5782f362641ead4da753697f484f59ca18078f5730883088180828009818180090909828080927ff3d3f7c6ec7eaf05b586273db0c292409ba27fa271808f8e5cbdf9e56fbbcb8d0883088180828009818180090909828080927f23dd8b576fa286331864d63c77fd82fa61da717533821b9382617ebd54abeb460883088180828009818180090909828080927fa7cc17e6f4f00d6bb6090ab547f5304d78b6386c68611597c0d8bf7f43aacbfe0883088180828009818180090909828080927f6f98269e5b461f1e0a4edc75d574a2b4e34cd21d0e3b7af7dca0092215ceb0a20883088180828009818180090909828080927fcf5210b2efc2241ebeaa55aeca7fb1148f4a29f3c643b874dff705d7781de1cc0883088180828009818180090909828080927f3df156c9f66b66b3f02b185ce503ea304bc876a019d20b0d26ce0a6c8308bb6e0883088180828009818180090909828080927f789a0dccf9b67ee59d33dae6bdd67349d656e5430fe635228a5cba1056977a460883088180828009818180090909828080927f6ab5fff302ec18001ad491b218c47bf0df3bd655d2454f160e16bdb8926f6b010883088180828009818180090909828080927f5bb7d0071f06646588a9ea2afcf4546e973d848e7a0738a32196368bde69701f0883088180828009818180090909828080927f62a2d1cf4a4ca616d98c8dbfec80697a07ee396c2a0fc08ef8bbcb533bd52b3d0883088180828009818180090909828080927fdbaa026275eb4def033cf764cc8618f80390f4664882b14c37fcca8759b89f270883088180828009818180090909828080927f775657d6ad46103ce00bbf79004bd37c147ae850f2dc425e099d5d5614059f220883088180828009818180090909828080927f4e61a6ea081de44f1e3b8db283b5cc635cea3e75951989ba8af6011a60aa40150883088180828009818180090909828080927f44dedebeae494420270dbb6942a8ed6428524870bc59b823e3b30f670edf39250883088180828009818180090909828080927f612aae4aab14ba9ad2137997aedc5260cf33d68a1a31a6de34af604c416e11680883088180828009818180090909828080927f88d869cee1f54bb7f88ec9d7868d6c7c4853157578ae03f2ef695a86708499bb0883088180828009818180090909828080927feedb0a063b7dc1f03f8e93988defce65913a8ba8dc0e9382677e76ae0c868d0f0883088180828009818180090909828080927f5abe0556f1b6cdc01e64bece120307961cac9fa8b86d558375db8bc7c826cdea0883088180828009818180090909828080927f7b4020e0625af3c0a94f42cb68d2793cb11eddd6f427fbd7fc224b09bc35d9b30883088180828009818180090909828080927fe9fe58498866232db2fea6c0a41cc03f76e634ee063ac68d56a0f1fdeff344b60883088180828009818180090909828080927f7069a5c1ab448edfc3a9cb07b2224957fc1bac936371ac27250156730c9b80790883088180828009818180090909828080927f6f13c2492208c1a3f33cc9f02f461279f855ce84fe77f5e29597925b6131f1950883088180828009818180090909828080927fe542243d3d82547243f858bf2bfb2a27fd8f8ea3f194d479dfc21ca58df7103d0883088180828009818180090909828080927fbbfbc0cb7f9206e17f81022078150aae7b9355992b6458c854f5a08355dad0420883088180828009818180090909828080927f94f0568cb0a7bb6f6b20bcf4dec92b0ac9e149312fdc4f1be26c605f5b3cc3500883088180828009818180090909828080927f483a9a75f05ad6c5c2501ae048d483e14ac25237e7934a6bf9e5b01abb9254e80883088180828009818180090909828080927fcae189fec307b78ba87c57dbb105ed6ac676dd7396bba9c4a94ddd1a3ace63db0883088180828009818180090909828080927f10ca0fd2a95bc198763d375f566182463e0c92ea122df6485f1c4e5a9769b32c0883088180828009818180090909828080927f8abed979216162a193fde6b6bb882963cb8d97ca96b5b5c360cca4b6d757db630883088180828009818180090909828080927fdfa3c38474b954d892b9d36f82c6258ebe41d8276278194218968a15f66b9ef908830881808280098181800909090860005260206000f3"


     # Instantiate and deploy contract
    miximus = w3.eth.contract(abi=miximus_interface['abi'], bytecode=miximus_interface['bin'])





    tx_hash = miximus.deploy(transaction={'from': w3.eth.accounts[0], 'gas': 4000000})

    # Get tx receipt to get contract address
    tx_receipt = w3.eth.waitForTransactionReceipt(tx_hash, 10000)
    miximus_address = tx_receipt['contractAddress']
    pdb.set_trace()

    return(miximus_address)


if __name__ == "__main__":
    contract_deploy()
```

This script deployed the hash function byte code to 0x769434C3da33aAaD9ACAb354B6fEf971f4634D68 address. 

Now we should be able to hash by calling `mimc.MiMCpe7` function in that smart contract. 


So now we add a few things to our smart contract to allow for deposits 

```
    function deposit(uint256 new_merkle_root, uint256[24] proof, bool[24] path, uint256 leaf) public {
        //TODO: Check that your leaf is correct its balance == value sent
        
        // Prove that at position x is 0 
        require(membership_proof(merkle_root, 0, proof, path));
        // Add your leaf to that position
        require(membership_proof(new_merkle_root, leaf, proof, path));
        // set the new merkle root
        merkle_root = new_merkle_root;

    }
    
    // this is a weird hack
    // I deployed https://github.com/iden3/circomlib/blob/master/src/mimc_printcontract.js 
    // bytecode manually and this is its address
    mimc_abi mimc = mimc_abi(0x769434C3da33aAaD9ACAb354B6fEf971f4634D68);
    
    function membership_proof(uint256 root, uint256 leaf, 
                        uint256[24] proof, bool[24] path) internal returns(bool) {
        for (uint i=0;i<proof.length;i++) {
            if (path[i]) {
                leaf = hash(leaf, proof[i]);
            }
            else {
                leaf = hash(proof[i], leaf);
            }
        }
        return(leaf == root);
    }
    
   function hash(uint256 in_x, uint256 in_k) view returns(uint256) {
        uint256 res = mimc.MiMCpe7(in_x,in_k);
        return(res);
    }

```

This should allow us to do deposits onto our side chain. Please be careful using this beacuse i did not have time to test it. 
But it should give you an example of how the deposit works.

Another way is to use another SNARK
```
include "../circomlib/circuits/mimc.circom";
include "../circomlib/circuits/eddsamimc.circom";
include "../circomlib/circuits/bitify.circom";

template Main(n) {
    signal input current_state;

    signal input last_index;
    
    signal input pubkey[2];
    signal input deposit;
    signal input token_type;

    signal private input paths2root[n-1];

    // Needed to avoid a DDoS
    // signal private input R8x;
    // signal private input R8y;
    // signal private input S;

    signal output new_state;
    signal output new_index;

    var i
    var j;
    
    last_index < 2**n;

    // computes account 
    component old_hash;
    component new_hash;

    component n2b;
    component old_merkle[n-1];
    component new_merkle[n-1];
    component verifier;
    
    var tmp_state = current_state;
    var tmp_index = last_index;
    //get path to root
    n2b = Num2Bits(n-1);
    tmp_index = tmp_index+i;
    n2b.in <== tmp_index;

    old_hash = MultiMiMC7(1,91);
    old_hash.in[0] <== 0;

    old_merkle[0] = MultiMiMC7(2,91);
    old_merkle[0].in[0] <== old_hash.out - n2b.out[0]* (old_hash.out - paths2root[0]);
    old_merkle[0].in[1] <== paths2root[0] - n2b.out[0]* (paths2root[0] - old_hash.out);

    for (j=1; j<n-1; j++){
        old_merkle[j] = MultiMiMC7(2,91);
        old_merkle[j].in[0] <== old_merkle[j-1].out - n2b.out[j]* (old_merkle[j-1].out - paths2root[j]);
        old_merkle[j].in[1] <== paths2root[j] - n2b.out[j]* (paths2root[j] - old_merkle[j-1].out);
        }

    tmp_state === old_merkle[n-2].out;

    // Needed to avoid a DDoS
    // verifier = EdDSAMiMCVerifier();   
    // verifier.enabled <== 1;
    // verifier.Ax <== pubkey[0];
    // verifier.Ay <== pubkey[1];
    // verifier.R8x <== R8x;
    // verifier.R8y <== R8y;
    // verifier.S <== S;
    // verifier.M <== pubkey[0];

    new_hash = MultiMiMC7(4,91);
    new_hash.in[0] <== pubkey[0];
    new_hash.in[1] <== deposit;
    new_hash.in[2] <== 0;
    new_hash.in[3] <== token_type;

    new_merkle[0] = MultiMiMC7(2,91);
    new_merkle[0].in[0] <== new_hash.out - n2b.out[0]* (new_hash.out - paths2root[0]);
    new_merkle[0].in[1] <== paths2root[0] - n2b.out[0]* (paths2root[0] - new_hash.out);

    for (j=1; j<n-1; j++){
        new_merkle[j] = MultiMiMC7(2,91);
        new_merkle[j].in[0] <== new_merkle[j-1].out - n2b.out[j]* (new_merkle[j-1].out - paths2root[j]);
        new_merkle[j].in[1] <== paths2root[j] - n2b.out[j]* (paths2root[j] - new_merkle[j-1].out);
        }
    tmp_state = new_merkle[n-2].out

    new_state <== new_merkle[n-2].out;
    new_index <== last_index+k;

    }

component main = Main(6);
```
 

### Withdraws

```
include "../circomlib/circuits/mimc.circom";
include "../circomlib/circuits/eddsamimc.circom";
include "../circomlib/circuits/bitify.circom";

template Main(n,k) {
    signal input current_state;
    
    signal private input pubkey[k][2];
    signal private input nonce[k];
    signal private input token_balance[k];

    signal input withdraw[k];
    signal input token_type[k];
    signal input withdraw_account[k];

    signal private input paths2root[k][n-1];
    signal private input paths2root_pos[k][n-1];

    signal private input R8x[k];
    signal private input R8y[k];
    signal private input S[k];

    signal output new_state;

    var i;
    var j;

    var NONCE_MAX_VALUE = 100;

    // computes account 
    component old_hash[k];
    component new_hash[k];
    component old_merkle[k][n-1];
    component new_merkle[k][n-1];
    component transaction[k];
    component verifier[k];
    var tmp_state = current_state;

    //get path to root
    for (i=0;i<k;i++){

        old_hash[i] = MultiMiMC7(4,91);
        old_hash[i].in[0] <== pubkey[i][0];
        old_hash[i].in[1] <== token_balance[i];
        old_hash[i].in[2] <== nonce[i];
        old_hash[i].in[3] <== token_type[i];

        old_merkle[i][0] = MultiMiMC7(2,91);
        old_merkle[i][0].in[0] <== old_hash[i].out - paths2root_pos[i][0] * (old_hash[i].out - paths2root[i][0]);
        old_merkle[i][0].in[1] <== paths2root[i][0] - paths2root_pos[i][0] * (paths2root[i][0] - old_hash[i].out);

        for (j=1; j<n-1; j++){
            old_merkle[i][j] = MultiMiMC7(2,91);
            old_merkle[i][j].in[0] <== old_merkle[i][j-1].out - paths2root_pos[i][j] * (old_merkle[i][j-1].out - paths2root[i][j]);
            old_merkle[i][j].in[1] <== paths2root[i][j] - paths2root_pos[i][j] * (paths2root[i][j] - old_merkle[i][j-1].out);
            }

        tmp_state === old_merkle[i][n-2].out;

        transaction[i] = MultiMiMC7(2,91);
        transaction[i].in[0] <== old_hash[i].out;
        transaction[i].in[1] <== withdraw_account[i];

        verifier[i] = EdDSAMiMCVerifier();   
        verifier[i].enabled <== 1;
        verifier[i].Ax <== pubkey[i][1];
        verifier[i].Ay <== pubkey[i][0];
        verifier[i].R8x <== R8x[i];
        verifier[i].R8y <== R8y[i];
        verifier[i].S <== S[i];
        verifier[i].M <== transaction[i].out;

        // balance checks
        token_balance[i] - withdraw[i] <= token_balance[i];

        nonce[i] != NONCE_MAX_VALUE;

        new_hash[i] = MultiMiMC7(4,91);
        new_hash[i].in[0] <== pubkey[i][0];
        new_hash[i].in[1] <== token_balance[i]-withdraw[i] ;
        new_hash[i].in[2] <== nonce[i]+1;
        new_hash[i].in[3] <== token_type[i];

        new_merkle[i][0] = MultiMiMC7(2,91);
        new_merkle[i][0].in[0] <== new_hash[i].out - paths2root_pos[i][0] * (new_hash[i].out - paths2root[i][0]);
        new_merkle[i][0].in[1] <== paths2root[i][0] - paths2root_pos[i][0] * (paths2root[i][0] - new_hash[i].out);

        for (j=1; j<n-1; j++){
            new_merkle[i][j] = MultiMiMC7(2,91);
            new_merkle[i][j].in[0] <== new_merkle[i][j-1].out - paths2root_pos[i][j] * (new_merkle[i][j-1].out - paths2root[i][j]);
            new_merkle[i][j].in[1] <== paths2root[i][j] - paths2root_pos[i][j] * (paths2root[i][j] - new_merkle[i][j-1].out);
            }
        tmp_state = new_merkle[i][n-2].out
        }
    
    new_state <== new_merkle[k-1][n-2].out;
    }

component main = Main(6,2);
```
## Prover race conditions

The prover takes x seconds to create a proof. Therefore we need the merkle root to be the same at the end of the proof as at the start. 

So we need to stagger the depsoits and withdraws that change the token balances.

## Prover logic

```
const eddsa = require("./snarks/circomlib/src/eddsa.js");
const snarkjs = require("snarkjs");
const MIMC = require('./snarks/circomlib/src/mimc7.js')
const assert = require('assert');
const fs = require('fs');

const NONCE_MAX_VALUE = 100;

function merkleTree(leafs, elements_to_proof){
 var i;
 var j;
 var h;
 const hash_leafs = leafs.map(x => MIMC.multiHash([x]));
 const hash_leafs_l = [[],[],[],[],[],[],[]];
 var tmp_elements_to_proof = elements_to_proof;
 const proofs = [[],[]];

 const tmp1 = elements_to_proof[0].toString(2).padStart(6,'0').split('').reverse();
 const tmp2 = elements_to_proof[1].toString(2).padStart(6,'0').split('').reverse();
 const paths = [tmp1.map(x => parseInt(x,10)),
     tmp2.map(x => parseInt(x,10))];

 //console.log(hash_leafs);
 hash_leafs_l[0] = hash_leafs;

 for (h = 1; h<6;h++){
  for (i = 0; i<parseInt(64/2**(h));i++){
   for (j = 0; j<2;j++){
    if (tmp_elements_to_proof[j] == 2*i){
     proofs[j].push(hash_leafs_l[h-1][2*i+1]);
    } else if (tmp_elements_to_proof[j] == 2*i+1){
     proofs[j].push(hash_leafs_l[h-1][2*i]);
    }
   }
   //console.log(h, i);
  hash_leafs_l[h].push(MIMC.multiHash([hash_leafs_l[h-1][2*i],hash_leafs_l[h-1][2*i+1]]))
  }
  tmp_elements_to_proof = tmp_elements_to_proof.map(x => Math.floor(x/2))
 }

 return [MIMC.multiHash([hash_leafs_l[5][0],hash_leafs_l[5][1]]), proofs, paths];
}

function merkleTree1(leafs, elements_to_proof){
 var i;
 var j;
 var h;
 const hash_leafs = leafs.map(x => MIMC.multiHash([x]));
 const hash_leafs_l = [[],[],[],[],[],[],[]];
 var tmp_elements_to_proof = elements_to_proof;
 const proofs = [[],[]];

 const tmp1 = elements_to_proof[0].toString(2).padStart(6,'0').split('').reverse();
 const paths = [tmp1.map(x => parseInt(x,10))];

 //console.log(hash_leafs);
 hash_leafs_l[0] = hash_leafs;

 for (h = 1; h<7;h++){
  for (i = 0; i<parseInt(64/2**(h));i++){
   for (j = 0; j<1;j++){
    if (tmp_elements_to_proof[j] == 2*i){
     proofs[j].push(hash_leafs_l[h-1][2*i+1]);
    } else if (tmp_elements_to_proof[j] == 2*i+1){
     proofs[j].push(hash_leafs_l[h-1][2*i]);
    }
   }
   //console.log(h, i);
  hash_leafs_l[h].push(MIMC.multiHash([hash_leafs_l[h-1][2*i],hash_leafs_l[h-1][2*i+1]]))
  }
  tmp_elements_to_proof = tmp_elements_to_proof.map(x => Math.floor(x/2))
 }

 return [MIMC.multiHash([hash_leafs_l[5][0],hash_leafs_l[5][1]]), proofs, paths];
}

function verifyTransfer(batchTransactions, leafsSet){	
	for (t in batchTransactions){

		const old_account_from = MIMC.multiHash([t.pubkey[0],t.token_balance_from,t.nonce,t.token_type]);
		assert(leafsSet.contains(old_account_from));

		const old_account_to = MIMC.multiHash([t.to[0],t.token_balance_to,t.nonce_to,t.token_type_to]);
		assert(leafsSet.contains(old_account_to));

		const msg = MIMC.multiHash([old_account_from, old_account_to]);

		assert(eddsa.verifyMiMC(t.pubKey, [t.R8x, t.R8y, t.S], msg));

		assert(t.token_balance_from - t.amount <= t.token_balance_from);
		assert(t.token_balance_to + t.amount >= t.token_balance_to);

		assert(t.nonce_from < NONCE_MAX_VALUE);
		assert(t.token_type_from == t.token_type_to);
	}	
}

function verifyDeposit(batchTransactions, leafsSet){	
	for (t in batchTransactions){
	}	
}

function verifyWithdraw(batchTransactions, leafsSet){	
	for (t in batchTransactions){

		const old_account_from = MIMC.multiHash([t.pubkey[0],t.token_balance_from,t.nonce,t.token_type]);
		assert(leafsSet.contains(old_account_from));

		const msg = MIMC.multiHash([old_account_from, t.withdraw]);

		assert(eddsa.verifyMiMC(t.pubKey, [t.R8x, t.R8y, t.S], msg));

		assert(t.token_balance_from - t.amount <= t.token_balance_from);

		assert(t.nonce_from < NONCE_MAX_VALUE);
		assert(t.token_type_from == t.token_type_to);
	}	
}

function generateWitnessDeposit(batchTransactions, leafsSet, current_state, current_index){
	verifyDeposit(batchTransactions, leafsSet);
	var index = current_index;
	var state = current_state;

	var pubkey = [];
	var deposit = [];
	var token_type = [];
	var paths2root = [];
	var i;

	for (i=0; i<batchTransactions.length;i++){
		let t = batchTransactions[i];
		pubkey = t.pubkey;

		deposit.push(t.deposit);
		token_type.push(t.token_type);
		let old_tree = merkleTree(leafsSet, [index,index]);
		paths2root = old_tree[1][0];
		let account = MIMC.multiHash([t.pubkey[0],t.deposit,0,t.token_type]);
		leafsSet[index] = account;
		let new_tree = merkleTree1(leafsSet, [index]);
		index = index+1;
		state = new_tree[0];
		console.log(state);
	}

	console.log(paths2root);
	const inputs = {
	current_state: current_state.toString(10),
	last_index: current_index.toString(10),
	pubkey: pubkey.map(x => x.toString(10)),
	deposit: deposit.map(x => x.toString(10)),
	token_type: (1).toString(10),
	paths2root: paths2root.map(x => x.toString(10)),
	new_state: state.toString(10),
	new_index: (current_index+batchTransactions.length).toString(10)
    }

	return inputs;
}

function generateWitnessTransfer(batchTransactions, leafsSet, current_state){
	verifyTransfer(batchTransactions, leafsSet);
	var index_proof = [];
	var state = current_state;
	for (t in batchTransactions){

		let old_account_from = MIMC.multiHash([t.pubkey[0],t.token_balance_from,t.nonce,t.token_type]);
		let old_account_to = MIMC.multiHash([t.to[0],t.token_balance_to,t.nonce_to,t.token_type_to]);

		leafsSet[leafsSet.indexOf(old_account_from)] = MIMC.multiHash([t.pubkey[0],t.token_balance_from-amount,t.nonce+1,t.token_type])
		leafsSet[leafsSet.indexOf(old_account_to)] = MIMC.multiHash([t.to[0],t.token_balance_to+amount,t.nonce_to+1,t.token_type])
		let tree = merkleTree(leafsSet, [leafsSet.indexOf(old_account_from), leafsSet.indexOf(old_account_to)]);
	}
}

function generateWitnessWithdraw(batchTransactions, leafsSet){
	verifyWithdraw(batchTransactions, leafsSet);
	var index_proof = [];
	for (t in batchTransactions){

		let old_account_from = MIMC.multiHash([t.pubkey[0],t.token_balance_from,t.nonce,t.token_type]);
		var index = leafsSet.indexOf(old_account_from)
		leafsSet[index] = MIMC.multiHash([t.pubkey[0],t.token_balance_from-amount,t.nonce+1,t.token_type])
		index_proof.push(index)
	}
	const tree = merkleTree(leafsSet, index_proof);
}
```


## Homework :P

We need to add deposits and withdraws to the tutorial

Instead of just storing the public key in the leaf we can store arbitrary information. Can you build

1. NFT
2. tweets on chain, 
3. votes
4. Staked tokens 

anything you can store in the EVM you can store here. 

## Disclaimer

1. Circom is not really fast enough to natively create proofs and trusted setups for merkle trees deeper than 12 hashes. or 2 trnasactions per block so we increase things
2. This does not undermine the central claim here that we can do 500 tps on ethereum for a large subset of dapp logics. The reason being that we can use circom as a user frindly developer enviroment and pass all the proving and setup requiremntes to bellman which is much faster. 
3. Even then bellman takes ~15 mintues to create a proof of AWS 40 core server. We can produce proofs in parallel that costs about 100 usd per proof. This is still sub sent per transaction which is really cheap compared to eth. 
