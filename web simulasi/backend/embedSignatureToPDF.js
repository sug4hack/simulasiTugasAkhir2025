// embedSignatureToPDF.js
const fs = require("fs");
const crypto = require("crypto");
const { PDFDocument } = require("pdf-lib");
const path = require("path");

// Marker + helper
const SIG_BEGIN = Buffer.from("\n%%SIG-CONTAINER-BEGIN\n");
const SIG_END   = Buffer.from("\n%%SIG-CONTAINER-END\n");
const sha256Hex = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

async function embedSignatureToPDF(inputPdfPath, outputPdfPath, { username, privateKeyPem, passphrase }) {
  const src = fs.readFileSync(inputPdfPath);
  if (!src.slice(0, 5).toString().startsWith("%PDF-")) {
    throw new Error("File bukan PDF valid");
  }

  // 1) Load & set metadata (ini bebas diubah)
  const pdfDoc = await PDFDocument.load(src);
  pdfDoc.setTitle(`Dokumen Tertandatangani oleh ${username}`);
  pdfDoc.setSubject("Simulasi Tugas Akhir");
  pdfDoc.setAuthor("Diskominfo Kota Kediri dan Poltek SSN");
  pdfDoc.setProducer("ASNDIGITAL DUMMY 2");
  const now = new Date();
  pdfDoc.setCreationDate(now);
  pdfDoc.setModificationDate(now);

  // 2) Save ke bytes FINAL KONTEN
  const contentBytes = await pdfDoc.save();

  // 3) Tanda tangani bytes final konten
  const signature = crypto.sign("sha256", contentBytes, {
    key: privateKeyPem,
    passphrase,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  });

  // 4) Buat kontainer tanda tangan (base64(JSON)) dan APPEND
  const container = {
    version: 1,
    alg: "RSA-SHA256",
    signer: username,
    ts: now.toISOString(),
    doc_sha256: sha256Hex(contentBytes),
    signature_b64: signature.toString("base64"),
  };
  const block = Buffer.concat([
    SIG_BEGIN,
    Buffer.from(Buffer.from(JSON.stringify(container)).toString("base64")),
    SIG_END,
  ]);

  fs.writeFileSync(outputPdfPath, Buffer.concat([contentBytes, block]));
}

module.exports = { embedSignatureToPDF, SIG_BEGIN, SIG_END, sha256Hex };
