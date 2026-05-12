// rotate_keys.js
'use strict';

require('dotenv').config();
const axios = require('axios');
const mysql = require('mysql2/promise');
const cron = require('node-cron');
const base64 = require('base-64');

// === Wrap (Sandi Data) ===
const { encryptSandidata } = require('./sandidata');

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

// ===== Wrap helper: ambil ciphertext string dari respon Sandi Data =====
async function wrapKey(plaintext) {
  const res = await encryptSandidata(plaintext);
  // ekspektasi format: { Ciphertext: [ { text: "<ciphertext>" } ] }
  const ct = res?.Ciphertext?.[0]?.text;
  if (!ct) throw new Error('Wrap gagal: response tidak memuat Ciphertext[0].text');
  return ct;
}

async function wrapTriple({ key16, key24, key32 }) {
  // bungkus paralel biar cepat
  const [w16, w24, w32] = await Promise.all([
    wrapKey(key16),
    wrapKey(key24),
    wrapKey(key32),
  ]);
  return { w16, w24, w32 };
}

function getWeekWindowJakarta(now = new Date()) {
  // Normalisasi waktu ke Asia/Jakarta
  const tz = new Date(now.toLocaleString('en-US', { timeZone: TZ }));
  const dow = tz.getDay();                 // 0=Sun..6=Sat
  const diffFromMonday = (dow + 6) % 7;    // jarak ke Senin
  tz.setDate(tz.getDate() - diffFromMonday);
  tz.setHours(0, 0, 0, 0);                 // Senin 00:00 WIB (start)
  const start = tz;

  const end = new Date(start);
  end.setDate(end.getDate() + 7);          // eksklusif (Senin berikutnya)

  return { tanggal_aktif: ymd(start), berlaku_sampai: ymd(end) };
}

// ====== DB helpers ======
/**
 * Pastikan ada 1 backup untuk window minggu (tanggal_aktif) saat ini.
 * Meng-insert backup baru jika belum ada.
 * Mengembalikan: true jika membuat baru; false jika sudah ada.
 */
async function ensureBackupForCurrentWindow(conn, tanggal_aktif, berlaku_sampai) {
  const [rows] = await conn.execute(
    `SELECT COUNT(*) AS cnt FROM kunci_mingguan WHERE is_backup = TRUE AND tanggal_aktif = ?`,
    [tanggal_aktif],
  );
  if ((rows[0]?.cnt || 0) > 0) return false;

  // generate & wrap backup
  const kunciBackup = await generateUniqueKeyPair();
  const wrappedBackup = await wrapTriple(kunciBackup);

  await conn.execute(
    `
    INSERT INTO kunci_mingguan (
      tanggal_aktif, berlaku_sampai,
      key_biasa, key_segera, key_penting, key_rahasia,
      is_backup, is_aktif
    )
    VALUES (?, ?, ?, ?, ?, ?, TRUE, FALSE)
  `,
    [tanggal_aktif, berlaku_sampai, wrappedBackup.w16, wrappedBackup.w16, wrappedBackup.w24, wrappedBackup.w32],
  );

  return true;
}

// ====== Mutex sederhana (hindari overlap dalam satu proses) ======
let rotating = false;
async function safeRotate() {
  if (rotating) {
    console.log('rotateKeys() dilewati: proses rotasi masih berjalan.');
    return;
  }
  rotating = true;
  try {
    await rotateKeys();
  } finally {
    rotating = false;
  }
}

// ====== ROTATION CORE (anchored to Monday 00:00 WIB) ======
async function rotateKeys() {
  // (Opsional tapi penting): anchor ke Senin 00:00 WIB, bukan ymd(now)
  const { tanggal_aktif, berlaku_sampai } = getWeekWindowJakarta(new Date());
  const conn = await mysql.createConnection(dbConfig);

  try {
    // 1) Idempotensi: jika sudah ada primary aktif utk minggu ini, cukup pastikan backup ada.
    const [existing] = await conn.execute(
      `SELECT id FROM kunci_mingguan WHERE tanggal_aktif = ? AND is_aktif = TRUE LIMIT 1`,
      [tanggal_aktif],
    );

    if (existing.length > 0) {
      try {
        await conn.beginTransaction();
        await ensureBackupForCurrentWindow(conn, tanggal_aktif, berlaku_sampai);
        await conn.commit();
      } catch (e) {
        try {
          await conn.rollback();
        } catch (_) {}
        console.error(`[${tanggal_aktif}] Gagal memastikan backup minggu ini:`, e.message);
      } finally {
        await conn.end();
      }
      console.log(`[${tanggal_aktif}] Primary aktif sudah ada. Validasi backup selesai.`);
      return;
    }

    // 2) Jika belum ada primary utk minggu ini → promosi backup minggu lalu menjadi primary.
    const [prevBackup] = await conn.execute(
      `SELECT id FROM kunci_mingguan WHERE is_backup = TRUE ORDER BY tanggal_aktif DESC LIMIT 1`,
    );

    if (prevBackup.length > 0) {
      const idCadangan = prevBackup[0].id;

      // Promosikan backup → jadi primary aktif minggu ini
      await conn.beginTransaction();
      await conn.execute(`UPDATE kunci_mingguan SET is_aktif = FALSE WHERE is_aktif = TRUE`);
      await conn.execute(
        `
        UPDATE kunci_mingguan
        SET is_backup = FALSE,
            is_aktif  = TRUE,
            tanggal_aktif  = ?,
            berlaku_sampai = ?
        WHERE id = ?
      `,
        [tanggal_aktif, berlaku_sampai, idCadangan],
      );

      // 2a) Coba buat backup baru utk minggu ini
      try {
        await ensureBackupForCurrentWindow(conn, tanggal_aktif, berlaku_sampai);
        await conn.commit();
        console.log(
          `[${tanggal_aktif}] Rotasi: backup minggu lalu dipromosikan → primary aktif. Backup baru dibuat.`,
        );
      } catch (e) {
        // Fallback: biarkan promosi tetap commit agar layanan tetap jalan.
        try {
          await conn.commit();
        } catch (_) {}
        console.warn(
          `[${tanggal_aktif}] /keygen gagal saat membuat backup baru. Fallback: primary aktif tanpa backup. Error: ${e.message}`,
        );

        // Upaya tambahan (opsional): bisa dijadwalkan retry out-of-band
      }

      await conn.end();
      return;
    }

    // 3) Tidak ada backup minggu lalu → kemungkinan awal siklus (cold start).
    //    Buat primary + backup sekaligus.
    try {
      const [kunciAktif, kunciBackup] = await Promise.all([generateUniqueKeyPair(), generateUniqueKeyPair()]);
      const [wrappedAktif, wrappedBackup] = await Promise.all([wrapTriple(kunciAktif), wrapTriple(kunciBackup)]);

      await conn.beginTransaction();

      // Nonaktifkan primary lama (jika ada)
      await conn.execute(`UPDATE kunci_mingguan SET is_aktif = FALSE WHERE is_aktif = TRUE`);

      // Primary (aktif)
      await conn.execute(
        `
        INSERT INTO kunci_mingguan (
          tanggal_aktif, berlaku_sampai,
          key_biasa, key_segera, key_penting, key_rahasia,
          is_backup, is_aktif
        )
        VALUES (?, ?, ?, ?, ?, ?, FALSE, TRUE)
      `,
        [tanggal_aktif, berlaku_sampai, wrappedAktif.w16, wrappedAktif.w16, wrappedAktif.w24, wrappedAktif.w32],
      );

      // Backup (nonaktif)
      await conn.execute(
        `
        INSERT INTO kunci_mingguan (
          tanggal_aktif, berlaku_sampai,
          key_biasa, key_segera, key_penting, key_rahasia,
          is_backup, is_aktif
        )
        VALUES (?, ?, ?, ?, ?, ?, TRUE, FALSE)
      `,
        [tanggal_aktif, berlaku_sampai, wrappedBackup.w16, wrappedBackup.w16, wrappedBackup.w24, wrappedBackup.w32],
      );

      await conn.commit();
      console.log(`[${tanggal_aktif}] Cold start: Primary & Backup dibuat (wrapped).`);
    } catch (e) {
      try {
        await conn.rollback();
      } catch (_) {}
      console.error(`[${tanggal_aktif}] Gagal cold start (primary+backup):`, e.message);
    } finally {
      await conn.end();
    }
  } catch (err) {
    try {
      await conn.end();
    } catch (_) {}
    console.error('Kesalahan rotasi:', err.message);
  }
}

// ====== Catch-up: buat backup jika hilang (dipanggil saat startup & Senin pagi) ======
async function ensureBackupIfMissing() {
  const { tanggal_aktif, berlaku_sampai } = getWeekWindowJakarta(new Date());
  const conn = await mysql.createConnection(dbConfig);
  try {
    // Pastikan ada primary aktif untuk minggu ini
    const [aktif] = await conn.execute(
      `SELECT id FROM kunci_mingguan WHERE tanggal_aktif = ? AND is_aktif = TRUE LIMIT 1`,
      [tanggal_aktif],
    );
    if (!aktif.length) return; // belum window minggu ini / belum ada primary

    // Cek apakah backup minggu ini sudah ada
    const [backup] = await conn.execute(
      `SELECT id FROM kunci_mingguan WHERE tanggal_aktif = ? AND is_backup = TRUE LIMIT 1`,
      [tanggal_aktif],
    );
    if (backup.length) return; // backup sudah ada, aman

    // Buat backup baru untuk window minggu ini
    await conn.beginTransaction();
    await ensureBackupForCurrentWindow(conn, tanggal_aktif, berlaku_sampai);
    await conn.commit();
    console.log(`[${tanggal_aktif}] Catch-up: backup dibuat setelah kegagalan awal.`);
  } catch (e) {
    try {
      await conn.rollback();
    } catch (_) {}
    console.warn(`[${tanggal_aktif}] Retry job gagal membuat backup: ${e.message}`);
  } finally {
    try {
      await conn.end();
    } catch (_) {}
  }
}

// ====== Jadwal ======
// Cron utama: setiap Senin 00:00 WIB (rotasi mingguan)
cron.schedule(
  '0 0 * * 1',
  async () => {
    console.log('Menjalankan rotasi kunci mingguan...');
    await safeRotate();
  },
  { timezone: TZ },
);

// ===== Startup catch-up: jalankan SEKALI saat proses hidup =====
let bootCatchupRan = false;

async function bootCatchupOnce() {
  if (bootCatchupRan) return;
  bootCatchupRan = true;
  try {
    await ensureBackupIfMissing(); // buat backup jika primary minggu ini ada tapi backup belum ada
  } catch (e) {
    console.warn('Startup catch-up error:', e.message);
  }
}

// Jalankan segera saat boot
bootCatchupOnce();

/* ===================
  Rekomendasi Skema DB:
  - UNIQUE (tanggal_aktif, is_backup)
  - UNIQUE (tanggal_aktif, is_aktif)
  Ini mencegah duplikasi backup/primary untuk minggu yang sama.
  Untuk multi-instance/cluster, pertimbangkan DB lock (GET_LOCK/RELEASE_LOCK).
=================== */