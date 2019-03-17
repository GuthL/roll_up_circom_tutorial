const eddsa = require("./src/eddsa.js");
const snarkjs = require("snarkjs");
const fs = require("fs");
const util = require("util");
const mimcjs = require("./src/mimc7.js");

const bigInt = snarkjs.bigInt;

const DEPTH = 6;

const prvKey_from = Buffer.from(
  "0000000000000000000000000000000000000000000000000000000000000001",
  "hex"
);
const prvKey_to = Buffer.from(
  "0000000000000000000000000000000000000000000000000000000000000002",
  "hex"
);

const pubKey_from = eddsa.prv2pub(prvKey_from);
const pubKey_to = eddsa.prv2pub(prvKey_to);

const nonce_from = 0;
const nonce_to = 0;

const token_type_from = 10;
const token_balance_from = 1000;
const token_type_to = 10;
const token_balance_to = 2000;
const amount = 100;

const old_hash_leaf_from = mimcjs.multiHash([
  pubKey_from[0],
  token_balance_from,
  nonce_from,
  token_type_from
]);
const old_hash_leaf_to = mimcjs.multiHash([
  pubKey_to[0],
  token_balance_to,
  nonce_to,
  token_type_to
]);

console.log(
  "We selected to place account 1 and 2 at index 0 and 1 of the Merkle Tree"
);
var old_merkle = new Array(DEPTH - 1);
old_merkle[0] = mimcjs.multiHash([old_hash_leaf_from, old_hash_leaf_to]);

var i;
for (i = 1; i < DEPTH - 1; i++) {
  old_merkle[i] = mimcjs.multiHash([old_merkle[i - 1], 0]);
}

console.log("Initial Root");
console.log(old_merkle[DEPTH - 2]);

const signature = eddsa.signMiMC(prvKey_from, old_hash_leaf_from);

const new_hash_leaf_from = mimcjs.multiHash([
  pubKey_from[0],
  token_balance_from - amount,
  nonce_from + 1,
  token_type_from
]);
const new_hash_leaf_to = mimcjs.multiHash([
  pubKey_to[0],
  token_balance_to + amount,
  nonce_to,
  token_type_to
]);

var new_merkle = new Array(DEPTH - 1);
new_merkle[0] = mimcjs.multiHash([new_hash_leaf_from, new_hash_leaf_to]);
var i;
for (i = 1; i < DEPTH - 1; i++) {
  new_merkle[i] = mimcjs.multiHash([new_merkle[i - 1], 0]);
}

console.log("Updated Root");
console.log(new_merkle[DEPTH - 2]);

const inputs = {
  paths2old_root_from: [old_hash_leaf_to.toString(), 0, 0, 0, 0],
  paths2old_root_to: [old_hash_leaf_from.toString(), 0, 0, 0, 0],
  paths2new_root_from: [new_hash_leaf_to.toString(), 0, 0, 0, 0],
  paths2new_root_to: [new_hash_leaf_from.toString(), 0, 0, 0, 0],
  paths2root_from_pos: [0, 0, 0, 0, 0],
  paths2root_to_pos: [1, 0, 0, 0, 0],

  current_state: old_merkle[DEPTH - 2].toString(),
  pubkey_x: pubKey_from[0].toString(),
  pubkey_y: pubKey_from[1].toString(),
  R8x: signature.R8[0].toString(),
  R8y: signature.R8[1].toString(),
  S: signature.S.toString(),
  nonce_from: nonce_from.toString(),
  to: pubKey_to[0].toString(),
  nonce_to: nonce_to.toString(),
  amount: amount.toString(),
  token_balance_from: token_balance_from.toString(),
  token_balance_to: token_balance_to.toString(),
  token_type_from: token_type_from.toString(),
  token_type_to: token_type_to.toString()
};

fs.writeFileSync(
  "./tokens_transfer_input.json",
  JSON.stringify(inputs),
  "utf-8"
);
