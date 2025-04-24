"use strict";

const blindSignatures = require('blind-signatures');
const NodeRSA = require('node-rsa');
const BigInteger = require('jsbn').BigInteger;
const { Coin, COIN_RIS_LENGTH, IDENT_STR, BANK_STR } = require('./coin.js');
const utils = require('./utils.js');

// Generate RSA keys
const rsa = new NodeRSA({ b: 2048 });
rsa.setOptions({ signingScheme: 'pkcs1-sha256' });

const pub = rsa.exportKey('components-public');
const priv = rsa.exportKey('components-private');

// Wrap all keys as BigIntegers
const n = new BigInteger(pub.n.toString('hex'), 16);
const e = new BigInteger(pub.e.toString(10), 10);
const d = new BigInteger(priv.d.toString('hex'), 16);

const BANK_KEY = {
  keyPair: {
    n,
    e,
    d
  }
};


// Sign a blinded hash
function signCoin(blindedCoinHash) {
  return blindSignatures.sign({
    blinded: blindedCoinHash,
    key: BANK_KEY,
  });
}

// Extract left/right hashes from coin string
function parseCoin(s) {
  const [cnst, amt, guid, leftHashes, rightHashes] = s.split('-');
  if (cnst !== BANK_STR) throw new Error("Invalid identity string");
  return [leftHashes.split(','), rightHashes.split(',')];
}

// Simulate a merchant accepting a coin
function acceptCoin(coin) {
  const valid = blindSignatures.verify({
    unblinded: coin.signature,
    message: coin.toString(),
    N: coin.n,
    E: coin.e,
  });

  if (!valid) throw new Error("Invalid coin signature");

  const [leftHashes, rightHashes] = parseCoin(coin.toString());
  let ris = [];

  for (let i = 0; i < COIN_RIS_LENGTH; i++) {
    const isLeft = utils.randInt(2) === 0;
    const ident = coin.getRis(isLeft, i);
    const expectedHash = isLeft ? leftHashes[i] : rightHashes[i];
    if (utils.hash(ident) !== expectedHash) {
      throw new Error(`Hash mismatch at index ${i}`);
    }
    ris.push(ident.toString('hex'));
  }

  return ris;
}

// Identify the double-spender or dishonest merchant
function determineCheater(guid, ris1, ris2) {
  for (let i = 0; i < ris1.length; i++) {
    if (ris1[i] === ris2[i]) continue;

    const part1 = Buffer.from(ris1[i], 'hex');
    const part2 = Buffer.from(ris2[i], 'hex');
    const xor = Buffer.alloc(part1.length);

    for (let j = 0; j < part1.length; j++) {
      xor[j] = part1[j] ^ part2[j];
    }

    const result = xor.toString();
    if (result.startsWith(IDENT_STR)) {
      console.log(`Coin ${guid} was double-spent by purchaser: ${result.split(':')[1]}`);
      return;
    } else {
      console.log(`Coin ${guid} was faked or reused by merchant.`);
      return;
    }
  }

  console.log(`Coin ${guid}: RIS strings identical. Possible mistake or reuse.`);
}

// === DEMO RUN ===

const coin = new Coin('alice', 20, n, e);
coin.signature = signCoin(coin.blinded);
coin.unblind();

const ris1 = acceptCoin(coin);
const ris2 = acceptCoin(coin);

console.log("Double-spend detection:");
determineCheater(coin.guid, ris1, ris2);

console.log("\nSame merchant reports again:");
determineCheater(coin.guid, ris1, ris1);
