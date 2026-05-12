// rotate_keys.js
require('dotenv').config();
const axios = require('axios');
const mysql = require('mysql2/promise');
const cron = require('node-cron');
const base64 = require('base-64');

// ===== Helpers ENV =====
const reqEnv = (k) => {
  const v = process.env[k];
  if (!v) throw new Error(`Missing env: ${k}`);
  return v;
};

// ===== Koneksi DB dari .env =====
const dbConfig = {
  host: reqEnv('DB_HOST'),
  user: reqEnv('DB_USER'),
  password: reqEnv('DB_PASS'),
  database: reqEnv('DB_NAME'),
};

// ===== Konfigurasi /keygen dari .env =====
const KEYGEN_URL  = reqEnv('KEYGEN_URL');    // contoh: http://10.0.0.1/keygen
const KEYGEN_USER = reqEnv('KEYGEN_USER');
const KEYGEN_PASS = reqEnv('KEYGEN_PASS');
const authHeader  = 'Basic ' + base64.encode(`${KEYGEN_USER}:${KEYGEN_PASS}`);

// ===== Timezone & tanggal helper (Asia/Jakarta) =====
const TZ = 'Asia/Jakarta';
const ymd = (d) =>
  new Intl.DateTimeFormat('en-CA', { timeZone: TZ, year:'numeric', month:'2-digit', day:'2-digit' }).format(d);
const addDays = (d, n) => new Date(d.getTime() + n * 86400000);

// ===== Call /keygen =====
async function generateUniqueKeyPair() {
  const response = await axios.post(KEYGEN_URL, {}, { headers: { Authorization: authHeader } });
  // expected: { data: { key16, key24, key32 } }
  return response.data.data;
}

// ===== Cleanup backup yang sudah melewati masa berlaku =====
// Catatan: kunci PRIMARY (is_backup=FALSE) tidak dihapus agar tetap bisa dekripsi dokumen lama.
async function cleanupExpiredBackups(conn) {
  await conn.execute(`
    DELETE FROM kunci_mingguan
    WHERE is_backup = TRUE
      AND DATE(berlaku_sampai) <= CURDATE()
  `);
}

async function rotateKeys() {
  const now = new Date();
  const tanggal_aktif   = ymd(now);
  const berlaku_sampai  = ymd(addDays(now, 7));

  const conn = await mysql.createConnection(dbConfig);

  try {
    // Jika sudah ada kunci aktif dengan tanggal hari ini (rotasi sudah berjalan), keluar.
    const [existing] = await conn.execute(`
      SELECT id FROM kunci_mingguan
      WHERE tanggal_aktif = ? AND is_aktif = TRUE
      LIMIT 1
    `, [tanggal_aktif]);

    if (existing.length > 0) {
      console.log(`[${tanggal_aktif}] Kunci aktif sudah ada. Tidak perlu generate.`);
      return;
    }

    // ===== Coba generate Primary & Backup =====
    let kunciAktif, kunciBackup;
    try {
      kunciAktif  = await generateUniqueKeyPair();
      kunciBackup = await generateUniqueKeyPair();
    } catch (err) {
      console.warn(`[${tanggal_aktif}] Gagal panggil /keygen. Fallback ke backup minggu lalu...`);

      // Ambil backup terakhir (minggu lalu) untuk dipromosikan
      const [cadangan] = await conn.execute(`
        SELECT id FROM kunci_mingguan
        WHERE is_backup = TRUE
        ORDER BY tanggal_aktif DESC
        LIMIT 1
      `);

      if (cadangan.length === 0) {
        console.error('Fallback gagal. Tidak ada backup tersedia.');
        return;
      }

      const idCadangan = cadangan[0].id;

      // Promosikan backup minggu lalu menjadi primary AKTIF untuk minggu ini.
      // Update tanggal_aktif dan berlaku_sampai ke minggu berjalan.
      await conn.beginTransaction();
      await conn.execute(`UPDATE kunci_mingguan SET is_aktif = FALSE WHERE is_aktif = TRUE`);
      await conn.execute(`
        UPDATE kunci_mingguan
        SET is_backup = FALSE,
            is_aktif = TRUE,
            tanggal_aktif = ?,
            berlaku_sampai = ?
        WHERE id = ?
      `, [tanggal_aktif, berlaku_sampai, idCadangan]);

      // Penting: JANGAN hapus backup lama pada skenario fallback.
      await conn.commit();

      console.log(`[${tanggal_aktif}] Fallback sukses. Backup dipromosikan menjadi primary aktif.`);
      return;
    }

    // ===== Sukses /keygen: simpan primary & backup baru =====
    await conn.beginTransaction();

    // Nonaktifkan primary lama
    await conn.execute(`UPDATE kunci_mingguan SET is_aktif = FALSE WHERE is_aktif = TRUE`);

    // Simpan PRIMARY (aktif untuk periode berjalan;)
    await conn.execute(`
      INSERT INTO kunci_mingguan (
        tanggal_aktif, berlaku_sampai,
        key_biasa, key_segera, key_penting, key_rahasia,
        is_backup, is_aktif
      )
      VALUES (?, ?, ?, ?, ?, ?, FALSE, TRUE)
    `, [
      tanggal_aktif, berlaku_sampai,
      kunciAktif.key16, // biasa
      kunciAktif.key16, // segera (pakai 16B juga)
      kunciAktif.key24, // penting
      kunciAktif.key32, // rahasia
    ]);

    // Simpan BACKUP (cadangan untuk rotasi pekan depan jika /keygen gagal)
    await conn.execute(`
      INSERT INTO kunci_mingguan (
        tanggal_aktif, berlaku_sampai,
        key_biasa, key_segera, key_penting, key_rahasia,
        is_backup, is_aktif
      )
      VALUES (?, ?, ?, ?, ?, ?, TRUE, FALSE)
    `, [
      tanggal_aktif, berlaku_sampai,
      kunciBackup.key16,
      kunciBackup.key16,
      kunciBackup.key24,
      kunciBackup.key32,
    ]);

    // Hapus hanya BACKUP yang masa berlakunya sudah lewat.
    await cleanupExpiredBackups(conn);

    await conn.commit();
    console.log(`[${tanggal_aktif}] Primary & Backup tersimpan. Primary aktif s.d. (${berlaku_sampai}).`);
  } catch (err) {
    try { await conn.rollback(); } catch (_) {}
    console.error('Kesalahan saat rotasi:', err.message);
  } finally {
    await conn.end();
  }
}

// ===== Cron: setiap Senin 00:00 WIB =====
cron.schedule('0 0 * * 1', () => {
  console.log('Menjalankan rotasi kunci mingguan...');
  rotateKeys();
}, { timezone: 'Asia/Jakarta' });

rotateKeys();