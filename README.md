/**
 * crypto_toolkit.ts
 *
 * Basic cryptographic utility with hashing, AES encryption, and key generation.
 */

import crypto from 'crypto';

class CryptoToolkit {
  hash(data:string, algo='sha256'){ return crypto.createHash(algo).update(data).digest('hex'); }
  genKey(length=32){ return crypto.randomBytes(length).toString('hex'); }
  encrypt(data:string,key:string){
    const iv=crypto.randomBytes(16);
    const cipher=crypto.createCipheriv('aes-256-cbc',Buffer.from(key.slice(0,32)),iv);
    let enc=cipher.update(data,'utf8','hex'); enc+=cipher.final('hex');
    return iv.toString('hex')+':'+enc;
  }
  decrypt(encrypted:string,key:string){
    const [ivHex,enc]=encrypted.split(':');
    const iv=Buffer.from(ivHex,'hex');
    const decipher=crypto.createDecipheriv('aes-256-cbc',Buffer.from(key.slice(0,32)),iv);
    let dec=decipher.update(enc,'hex','utf8'); dec+=decipher.final('utf8');
    return dec;
  }
}

const tool=new CryptoToolkit();
const key=tool.genKey();
const msg='Top secret message!';
const enc=tool.encrypt(msg,key);
const dec=tool.decrypt(enc,key);
console.log('Original:',msg);
console.log('Encrypted:',enc);
console.log('Decrypted:',dec);
