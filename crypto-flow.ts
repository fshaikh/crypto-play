import * as crypto from "crypto";

//#region Server Flow

interface ServerResponse {
    payload: Buffer;
    hash: string;
    signature: string;
    publicKey: any;
}

function getServerResponse(): ServerResponse{
    // Generate Public/Private Key pair
    const keys = generateKeys();
    // Confidentiality: Encrypt the payload
    const encryptedPayload = encrypt(getPayload(),keys.privateKey);
    // Integrity: Generate hash
    const hash = getHash(encryptedPayload);
    // Non-Repudiation: Generate Digital signature
    const signature = generateDigitalSignature(hash,keys.privateKey);
    return {
        payload: encryptedPayload,
        hash,
        signature,
        publicKey: keys.publicKey,
        
    }
}
function getPayload() {
  const payload = {
    name: "John",
    email: "john@gmail.com",
  };
  return payload;
}
/**
 * Generate Public/Private key pair. Public key will be shared with client
 */
function generateKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 4096,
  });
  return { publicKey, privateKey };
}
/**
 * Encrypt payload using server's private key
 */
function encrypt(payload: any, privateKey: any): Buffer {
    return crypto.privateEncrypt(privateKey, Buffer.from(JSON.stringify(payload)));
}
/**
 * Generate a hash of payload
 */
function getHash(encryptedPayload) {
    return crypto.createHash('sha256').update(encryptedPayload).digest('hex');
}

/**
 * Generate digital signature for a given payload
 */
function generateDigitalSignature(data: any,privateKey) {
   return crypto.createSign('RSA-SHA256').update(data).sign(privateKey,'hex')
}
//#endregion Server Flow

//#region Client Flow
callServer();

function callServer(){
    const {payload, hash,signature,publicKey} = getServerResponse();

    // Integrity: Verify the payload has not been modified
    if(!verifyHash(payload,hash)){
        console.log('Payload has been modified. Aborting');
        return;
    }

    // Non-repudiation: Verify the authenticity of the sender
    if(!verifyDigitalSignature(hash,signature,publicKey)){
        console.log('Signature mismatch. Aborting');
        return;
    } 

    // Confidentiality: Decrypt the payload
    const decryptedPayload = decrypt(payload,publicKey);
    console.log(JSON.parse(decryptedPayload).email);
}
function decrypt(encryptedPayload: any, publicKey: any) {
    const decryptedPayload = crypto.publicDecrypt(publicKey, encryptedPayload);
    return decryptedPayload.toString();
}

function verifyHash(payload:any,hash) {
    const computedHash = getHash(payload);
    return computedHash === hash;
}

function verifyDigitalSignature(hash, signature,publicKey) {
    return crypto.createVerify('RSA-SHA256').update(hash).verify(publicKey,signature,'hex');
}
//#endregion Client Flow



