const fs = require('fs');
const https = require('https');
const axios = require('axios');
require('dotenv').config();

// ==== ENV & Defaults ====
const SANDIDATA_DIR = process.env.SANDIDATA_DIR;
const SANDIDATA_BASE_URL = process.env.SANDIDATA_BASE_URL;

// ==== HTTPS Agent & Axios Instance (dibuat sekali) ====
function buildHttpsAgent() {
  const certFile = fs.readFileSync(`${SANDIDATA_DIR}/client.crt`);
  const keyFile = fs.readFileSync(`${SANDIDATA_DIR}/client.key`);
  

  const agentOptions = {
    cert: certFile,
    key: keyFile,
    rejectUnauthorized: false,
  };

  return new https.Agent(agentOptions);
}

const httpsAgent = buildHttpsAgent();

const http = axios.create({
  baseURL: SANDIDATA_BASE_URL,
  httpsAgent,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000, // 30 detik timeout
});

// ==== API ====
/**
 * Enkripsi plaintext via endpoint /seal (mTLS)
 * Payload mengikuti format awal:
 * {
 *   "Plaintext": [{ "Text": "<plaintext>" }]
 * }
 * @param {string} plaintext
 * @returns {Promise<any|null>} response.data atau null jika gagal
 */
async function encryptSandidata(plaintext) {
  try {
    const postData = {
      Plaintext: [{ Text: plaintext }],
    };

    const { data } = await http.post('/seal', JSON.stringify(postData));
    return data;
  } catch (error) {
    if (error.response) {
      console.error('Error encrypt:', error.response.status, error.response.data);
    } else {
      console.error('Error encrypt:', error.message);
    }
    return null;
  }
}

/**
 * Dekripsi ciphertext via endpoint /unseal (mTLS)
 * Payload mengikuti format awal:
 * {
 *   "Ciphertext": [{ "text": "<ciphertext>" }]
 * }
 * @param {string} ciphertext
 * @returns {Promise<string|null>} plaintext (string) atau null jika gagal
 */
async function decryptSandidata(ciphertext) {
  try {
    const postData = {
      Ciphertext: [{ text: ciphertext }],
    };

    const { data } = await http.post('/unseal', JSON.stringify(postData));
    return data?.Plaintext?.[0]?.text || null;
  } catch (error) {
    if (error.response) {
      console.error('Error decrypt:', error.response.status, error.response.data);
    } else {
      console.error('Error decrypt:', error.message);
    }
    return null;
  }
}

module.exports = { encryptSandidata, decryptSandidata };
