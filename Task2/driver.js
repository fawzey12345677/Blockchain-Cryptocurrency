"use strict";

let blindSignatures = require('blind-signatures');

let SpyAgency = require('./spyAgency.js').SpyAgency;

function makeDocument(coverName) {
  return `The bearer of this signed document, ${coverName}, has full diplomatic immunity.`;
}

function blind(msg, n, e) {
  return blindSignatures.blind({
    message: msg,
    N: n,
    E: e,
  });
}

function unblind(blindingFactor, sig, n) {
  return blindSignatures.unblind({
    signed: sig,
    N: n,
    r: blindingFactor,
  });
}

let agency = new SpyAgency();

// Create 10 cover identities
const coverNames = [
  "James Bond",
  "Jason Bourne",
  "Ethan Hunt",
  "Natasha Romanoff",
  "Jack Ryan",
  "Sydney Bristow",
  "George Smiley",
  "Napoleon Solo",
  "Aaron Cross",
  "Evelyn Salt"
];

// Prepare the documents and blind them
const originalDocs = [];
const blindingFactors = [];
const blindDocs = [];

for (let i = 0; i < 10; i++) {
  // Create the document
  const doc = makeDocument(coverNames[i]);
  originalDocs.push(doc);
  
  // Get the hash of the document
  const hash = blindSignatures.messageToHash(doc);
  
  // Blind the hash
  const { blinded, r } = blind(hash, agency.n, agency.e);
  
  // Store the blinded hash and the blinding factor
  blindDocs.push(blinded);
  blindingFactors.push(r);
}

agency.signDocument(blindDocs, (selected, verifyAndSign) => {
  // Create arrays for verification
  const verificationBlindingFactors = [];
  const verificationDocs = [];
  
  // Fill arrays with correct data for verification
  for (let i = 0; i < 10; i++) {
    if (i === selected) {
      // For the selected document, use undefined
      verificationBlindingFactors.push(undefined);
      verificationDocs.push(undefined);
    } else {
      // For other documents, provide the blinding factor and original doc
      verificationBlindingFactors.push(blindingFactors[i]);
      verificationDocs.push(originalDocs[i]);
    }
  }
  
  // Get the blinded signature
  const blindSig = verifyAndSign(verificationBlindingFactors, verificationDocs);
  
  // Unblind the signature
  const signature = unblind(blindingFactors[selected], blindSig, agency.n);
  
  // Verify the signature
  const hash = blindSignatures.messageToHash(originalDocs[selected]);
  const isValid = blindSignatures.verify({
    unblinded: signature,
    message: hash,
    N: agency.n,
    E: agency.e
  });
  
  console.log(`Document for ${coverNames[selected]} was signed.`);
  console.log(`Signature valid: ${isValid}`);
  
  if (isValid) {
    console.log(`Signed document: ${originalDocs[selected]}`);
    console.log(`Signature: ${signature}`);
  } else {
    console.log("Error: Signature verification failed!");
  }
});