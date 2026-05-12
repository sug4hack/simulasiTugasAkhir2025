const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const validKeyLengths = [16, 24, 32];

function encryptFile(inputPath, outputPath, keyBase64, aad = "") {
  return new Promise((resolve, reject) => {
    const key = Buffer.from(keyBase64, 'base64');

    if (!validKeyLengths.includes(key.length)) {
      return reject(new Error(`Invalid key length: ${key.length} bytes`));
    }

    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(Buffer.from(aad));

    const input = fs.createReadStream(inputPath);
    const output = fs.createWriteStream(outputPath);

    input.pipe(cipher).pipe(output);

    output.on('finish', () => {
      const authTag = cipher.getAuthTag();
      const finalData = Buffer.concat([nonce, authTag, fs.readFileSync(outputPath)]);
      fs.writeFileSync(outputPath, finalData);
      resolve();
    });

    output.on('error', reject);
    input.on('error', reject);
  });
}

module.exports = { encryptFile };
