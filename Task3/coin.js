"use strict";

const blindSignatures = require('blind-signatures');
const utils = require('./utils.js');

const COIN_RIS_LENGTH = 20;
const IDENT_STR = "IDENT";
const BANK_STR = "ELECTRONIC_PIGGYBANK";

class Coin {
  constructor(purchaser, amount, n, e) {
    this.amount = amount;
    this.n = n;
    this.e = e;
    this.guid = utils.makeGUID();
    this.leftIdent = [];
    this.rightIdent = [];

    let leftHashes = [];
    let rightHashes = [];

    for (let i = 0; i < COIN_RIS_LENGTH; i++) {
      let { key, ciphertext } = utils.makeOTP({ string: `${IDENT_STR}:${purchaser}` });

      this.leftIdent.push(key);
      leftHashes.push(utils.hash(key));

      this.rightIdent.push(ciphertext);
      rightHashes.push(utils.hash(ciphertext));
    }

    this.coinString = `${BANK_STR}-${this.amount}-${this.guid}-${leftHashes.join(',')}-${rightHashes.join(',')}`;
    this.blind();
  }

  blind() {
    let { blinded, r } = blindSignatures.blind({
      message: this.toString(),
      N: this.n,
      E: this.e,
    });
    this.blinded = blinded;
    this.blindingFactor = r;
  }

  unblind() {
    this.signature = blindSignatures.unblind({
      signed: this.signature,
      N: this.n,
      r: this.blindingFactor,
    });
  }

  toString() {
    return this.coinString;
  }

  getRis(isLeft, i) {
    return isLeft ? this.leftIdent[i] : this.rightIdent[i];
  }
}

module.exports = { Coin, COIN_RIS_LENGTH, IDENT_STR, BANK_STR };
