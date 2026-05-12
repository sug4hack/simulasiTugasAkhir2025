// const { execSync } = require("child_process");
// const fs = require("fs");
// const path = require("path");
// const readline = require("readline");

// const username = process.argv[2];

// if (!username) {
//   console.error("❌ Gunakan: node generate-user-cert.js <username>");
//   process.exit(1);
// }

// const rl = readline.createInterface({
//   input: process.stdin,
//   output: process.stdout,
//   terminal: true
// });

// function promptPassphrase(question) {
//   return new Promise((resolve) => {
//     rl.stdoutMuted = true;
//     rl.question(question, (value) => {
//       rl.history = rl.history.slice(1);
//       rl.close();
//       resolve(value);
//     });

//     rl._writeToOutput = function _writeToOutput(stringToWrite) {
//       if (rl.stdoutMuted) rl.output.write("*");
//       else rl.output.write(stringToWrite);
//     };
//   });
// }

// (async () => {
//   const passphrase = await promptPassphrase("🔐 Masukkan passphrase untuk mengenkripsi private key: ");
//   console.log("\n");

//   const caDir = path.resolve(__dirname, "ca");
//   const certsDir = path.resolve(__dirname, "certs");
//   if (!fs.existsSync(certsDir)) fs.mkdirSync(certsDir);

//   const userKey = path.join(certsDir, `${username}.key.pem`);
//   const userCsr = path.join(certsDir, `${username}.csr.pem`);
//   const userCert = path.join(certsDir, `${username}.cert.pem`);

//   try {
//     console.log(`🔑 Membuat private key terenkripsi untuk ${username}...`);
//     execSync(`openssl genrsa -aes256 -passout pass:${passphrase} -out "${userKey}" 2048`);

//     console.log(`📄 Membuat CSR...`);
//     execSync(`openssl req -new -key "${userKey}" -out "${userCsr}" -passin pass:${passphrase} -subj "/CN=${username}"`);

//     console.log(`✅ Menandatangani CSR menggunakan Root CA...`);
//     execSync(`openssl ca -config "${caDir}/openssl.cnf" -in "${userCsr}" -out "${userCert}" -batch`);

//     console.log(`\n🎉 Sertifikat berhasil dibuat:
//     - 🔐 Private Key: ${userKey}
//     - 📄 CSR:         ${userCsr}
//     - 🏅 Sertifikat:  ${userCert}`);
//   } catch (err) {
//     console.error("❌ Gagal membuat sertifikat:", err.message);
//   }
// })();

const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const readline = require("readline");

const username = process.argv[2];
if (!username) {
  console.error("❌ Gunakan: node generate-user-cert.js <username>");
  process.exit(1);
}

// Konfigurasi masa berlaku (default 730 hari = ±2 tahun)
const CERT_DAYS = parseInt(process.env.CERT_DAYS || "730", 10);

const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
function promptPassphrase(question) {
  return new Promise((resolve) => {
    rl.stdoutMuted = true;
    rl.question(question, (value) => {
      rl.history = rl.history.slice(1);
      rl.close();
      resolve(value);
    });
    rl._writeToOutput = function (str) {
      if (rl.stdoutMuted) rl.output.write("*");
      else rl.output.write(str);
    };
  });
}

(async () => {
  const passphrase = await promptPassphrase("🔐 Masukkan passphrase untuk mengenkripsi private key: ");
  console.log("\n");

  const caDir = path.resolve(__dirname, "ca");
  const certsDir = path.resolve(__dirname, "certs");
  if (!fs.existsSync(certsDir)) fs.mkdirSync(certsDir, { recursive: true });

  const userKey  = path.join(certsDir, `${username}.key.pem`);
  const userCsr  = path.join(certsDir, `${username}.csr.pem`);
  const userCert = path.join(certsDir, `${username}.cert.pem`);

  try {
    // 1) Private key terenkripsi AES-256
    console.log(`🔑 Membuat private key terenkripsi untuk ${username}...`);
    execFileSync("openssl", [
      "genrsa", "-aes256",
      "-passout", `pass:${passphrase}`,
      "-out", userKey, "2048"
    ], { stdio: "inherit" });

    // 2) CSR dengan subject CN=<username>
    console.log(`📄 Membuat CSR...`);
    execFileSync("openssl", [
      "req", "-new",
      "-key", userKey,
      "-out", userCsr,
      "-passin", `pass:${passphrase}`,
      "-subj", `/CN=${username}`
    ], { stdio: "inherit" });

    // 3) Sign CSR pakai CA -> sertifikat 2 tahun, sha256, ekstensi usr_cert
    //    Pastikan backend/ca/openssl.cnf punya bagian [ usr_cert ]
    console.log(`✅ Menandatangani CSR menggunakan Root CA (masa berlaku ${CERT_DAYS} hari)...`);
    execFileSync("openssl", [
      "ca",
      "-config", path.join(caDir, "openssl.cnf"),
      "-in", userCsr,
      "-out", userCert,
      "-batch",
      "-days", String(CERT_DAYS),
      "-md", "sha256",
      "-notext",
      "-extensions", "usr_cert"
    ], { stdio: "inherit" });

    // 4) Tampilkan ringkasan sertifikat
    console.log("\n📜 Ringkasan sertifikat:");
    execFileSync("openssl", ["x509", "-in", userCert, "-noout", "-subject", "-dates"], { stdio: "inherit" });

    console.log(`\n🎉 Sertifikat berhasil dibuat:
    - 🔐 Private Key : ${userKey}
    - 📄 CSR         : ${userCsr}
    - 🏅 Sertifikat  : ${userCert}
    (Masa berlaku: ${CERT_DAYS} hari)\n`);
  } catch (err) {
    console.error("❌ Gagal membuat sertifikat:", err.message);
    process.exit(1);
  }
})();
