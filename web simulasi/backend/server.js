// ===== backend/server.js =====
const dotenv = require('dotenv'); dotenv.config();

const express = require('express');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const FormData = require('form-data');
const bcrypt = require('bcryptjs');
const db = require('./db');
const os = require('os');
const crypto = require('crypto');
const { embedSignatureToPDF } = require('./embedSignatureToPDF');
const { decryptSandidata } = require('./sandidata');
const { pipeline } = require('stream/promises');
const { SIG_BEGIN, SIG_END, sha256Hex } = require('./embedSignatureToPDF');


// ---------- ENV HELPERS ----------
const get = (k, def = null) => (process.env[k] ?? def);
const reqEnv = (k) => {
  const v = process.env[k];
  if (!v) { console.error(`Missing required env: ${k}`); process.exit(1); }
  return v;
};

// ---------- LOAD CONFIG FROM .env ----------
const NODE_ENV = get('NODE_ENV', 'development');
const PORT = parseInt(get('PORT', '3000'), 10);

const FRONTEND_DIR = path.resolve(__dirname, get('FRONTEND_DIR', '../frontend'));
const UPLOADS_DIR = path.resolve(__dirname, get('UPLOADS_DIR', './uploads'));
const MAX_UPLOAD_MB = parseInt(get('MAX_UPLOAD_MB', '5'), 10);

const CORS_ALLOWED_ORIGINS = (get('CORS_ALLOWED_ORIGINS', '') || '')
  .split(',').map(s => s.trim()).filter(Boolean);

const CRYPT_BASE_URL   = reqEnv('CRYPT_BASE_URL');      // contoh: http://127.0.0.1:9081
const CRYPT_BASIC_USER = reqEnv('CRYPT_BASIC_USER');    // basic auth user untuk layanan kripto
const CRYPT_BASIC_PASS = reqEnv('CRYPT_BASIC_PASS');    // basic auth pass
const CRYPT_TIMEOUT_MS = parseInt(get('CRYPT_TIMEOUT_MS', '60000'), 10);

const SIGN_CERTS_DIR = path.resolve(__dirname, get('SIGN_CERTS_DIR', './certs'));

// ---------- INITIALIZE ----------
const app = express();

// CORS whitelist (kosong = longgar; produksi sebaiknya whitelist)
const corsOptions = CORS_ALLOWED_ORIGINS.length
  ? {
      origin: (origin, cb) => {
        if (!origin || CORS_ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
        return cb(new Error('Not allowed by CORS'));
      },
      credentials: false
    }
  : {};
app.use(cors(corsOptions));

app.use(express.json());
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
app.use(express.static(FRONTEND_DIR));
app.use('/uploads', express.static(UPLOADS_DIR)); // NOTE: lindungi di produksi bila perlu

// Multer (upload PDF)
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOADS_DIR),
  filename: (_, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    if (!file.originalname.toLowerCase().endsWith('.pdf')) return cb(new Error('Only PDF allowed'));
    cb(null, true);
  }
});

// Axios instance untuk layanan kripto (encrypt/decrypt)
const cryptoApi = axios.create({
  baseURL: CRYPT_BASE_URL,
  auth: { username: CRYPT_BASIC_USER, password: CRYPT_BASIC_PASS },
  timeout: CRYPT_TIMEOUT_MS,
  maxContentLength: Infinity,
  maxBodyLength: Infinity
});

// ---------- RESPONSE HELPERS ----------
const ok = (res, data = {}, extra = {}) => res.json({ success: true, ...extra, ...(data ? { data } : {}) });
const fail = (res, status, message = 'Terjadi kesalahan', extra = {}) =>
  res.status(status).json({ success: false, message, ...extra });

// ---------- DOMAIN HELPERS ----------
async function getKeyByDate(date, klasifikasiRaw) {
  const klasifikasi = String(klasifikasiRaw || '').toLowerCase();
  if (!date) throw new Error('Tanggal tidak disediakan');
  if (!['biasa','segera','penting','rahasia'].includes(klasifikasi)) {
    throw new Error('Klasifikasi tidak valid');
  }

  const [rows] = await db.execute(
    `SELECT * FROM kunci_mingguan
     WHERE tanggal_aktif <= ? AND berlaku_sampai >= ?
     ORDER BY tanggal_aktif DESC
     LIMIT 1`,
    [date, date]
  );

  if (!rows.length) throw new Error('Kunci tidak ditemukan untuk tanggal tersebut');

  const k = rows[0];
  switch (klasifikasi) {
    case 'biasa':
    case 'segera':  return k.key_biasa || k.key_segera;
    case 'penting': return k.key_penting;
    case 'rahasia': return k.key_rahasia;
  }
  throw new Error('Klasifikasi tidak valid'); // fallback
}

const safeBasename = (p) => path.basename(p || '');

// ---------- ROUTES ----------
// di server.js, sebelum daftar route:
const api = express.Router();

// Register
app.post('/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return fail(res, 400, 'Wajib isi username dan password');
  }
  try {
    const [existing] = await db.execute('SELECT id FROM users WHERE username = ?', [username]);
    if (existing.length) return fail(res, 400, 'Username sudah digunakan');

    const hashed = await bcrypt.hash(password, 10);
    await db.execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed]);
    return ok(res);
  } catch (err) {
    console.error('Register error:', err);
    return fail(res, 500, 'Gagal registrasi');
  }
});

// Login
// app.post('/login', async (req, res) => {
//   const { username, password } = req.body || {};
//   if (!username || !password) return fail(res, 400, 'Wajib isi username dan password');

//   try {
//     const [users] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
//     if (!users.length) return ok(res, null, { user: null }); // tidak bocorkan info

//     const match = await bcrypt.compare(password, users[0].password);
//     if (match) return ok(res, null, { user: username });

//     return ok(res, null, { user: null });
//   } catch (err) {
//     console.error('Login error:', err);
//     return fail(res, 500, 'Gagal login');
//   }
// });

// ===== Secure Login (drop-in replacement) =====


// Hapus surat
// di atas: const bcrypt = require('bcrypt'); const rateLimit = require('express-rate-limit');

const DUMMY_HASH = process.env.DUMMY_HASH;
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 20,                  // max 20 percobaan
  standardHeaders: true,
  legacyHeaders: false,
});

app.post('/login', loginLimiter, async (req, res) => {
  const username = (req.body?.username || '').trim();
  const password = (req.body?.password || '');

  if (!username || !password) return fail(res, 400, 'Wajib isi username dan password');
  try {
    // Ambil user
    const [rows] = await db.execute(
      'SELECT id, username, password FROM users WHERE username = ? LIMIT 1',
      [username]
    );
    const user = rows[0];

    // Pakai dummy hash jika user tidak ada (menyamakan waktu eksekusi)
    const hash = user ? user.password : DUMMY_HASH;

    const match = await bcrypt.compare(password, hash);
    if (!match || !user) {
      // Kegagalan generik: tidak beberkan apakah user ada atau tidak
      return fail(res, 401, 'Username atau password salah');
    }

    // Sukses
    return ok(res, null, { user: user.username }); // atau kirim token/session jika ada
  } catch (err) {
    console.error('Login error:', err);
    return fail(res, 500, 'Gagal login');
  }
});


app.delete('/hapus-surat/:id', async (req, res) => {
  const id = req.params.id;
  const { filePath } = req.body || {};
  if (!id) return fail(res, 400, 'ID surat tidak valid');

  try {
    await db.execute('DELETE FROM pengiriman_surat WHERE surat_id = ?', [id]);
    await db.execute('DELETE FROM surat WHERE id = ?', [id]);

    if (filePath) {
      // sanitize hanya ambil nama file
      const fileName = safeBasename(filePath);
      const fullPath = path.join(UPLOADS_DIR, fileName);
      if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    }
    return ok(res);
  } catch (err) {
    console.error('Gagal menghapus surat:', err);
    return fail(res, 500, 'Gagal menghapus surat');
  }
});

// Input surat masuk manual
app.post('/surat-masuk-manual', upload.single('file'), async (req, res) => {
  try {
    const { nomor_surat, perihal, tanggal_surat, pengirim, klasifikasi, penerima, nama_dokumen } = req.body || {};
    const file = req.file;

    if (!file) return fail(res, 400, 'File PDF wajib diunggah');
    if (!nomor_surat || !perihal || !tanggal_surat || !pengirim || !klasifikasi || !penerima || !nama_dokumen) {
      fs.existsSync(file.path) && fs.unlinkSync(file.path);
      return fail(res, 400, 'Field wajib tidak lengkap');
    }

    const key = await getKeyByDate(tanggal_surat, klasifikasi);
    // decrypt key
    const decryptedKey = await decryptSandidata(key);

    const [result] = await db.execute(
      `INSERT INTO surat (nomor_surat, perihal, tanggal_surat, klasifikasi, pengirim, nama_dokumen)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [nomor_surat, perihal, tanggal_surat, klasifikasi, pengirim, nama_dokumen]
    );
    const id = result.insertId;

    const form = new FormData();
    form.append('file', fs.createReadStream(file.path));
    form.append('key', decryptedKey);
    form.append('aad', String(id));

    const resp = await cryptoApi.post('/encrypt', form, {
      headers: form.getHeaders(),
      responseType: 'stream'
    });

    const encFile = `${Date.now()}-${file.originalname}.enc`;
    const encPath = path.join(UPLOADS_DIR, encFile);

    await new Promise((resolve, reject) => {
      const ws = fs.createWriteStream(encPath);
      resp.data.pipe(ws);
      resp.data.on('end', resolve);
      resp.data.on('error', reject);
    });

    fs.existsSync(file.path) && fs.unlinkSync(file.path);

    await db.execute('UPDATE surat SET file_path = ? WHERE id = ?', [path.join('uploads', encFile), id]);
    await db.execute(
      'INSERT INTO pengiriman_surat (surat_id, pengirim, penerima, status) VALUES (?, ?, ?, ?)',
      [id, pengirim, penerima, 'diterima']
    );

    return ok(res);
  } catch (err) {
    console.error('Surat masuk manual error:', err);
    return fail(res, 500, err.message || 'Gagal input surat masuk');
  }
});
// Upload surat keluar
app.post('/upload-surat-keluar', upload.single('file'), async (req, res) => {
  try {
    const { nomor_surat, tahun, perihal, tanggal_surat, klasifikasi, pengirim, penandatangan, nama_dokumen } = req.body || {};
    const file = req.file;

    if (!file) return fail(res, 400, 'File PDF wajib diunggah');
    if (!nomor_surat || !tahun || !perihal || !tanggal_surat || !klasifikasi || !pengirim || !nama_dokumen) {
      // penandatangan opsional sesuai skema kamu
      fs.existsSync(file.path) && fs.unlinkSync(file.path);
      return fail(res, 400, 'Field wajib tidak lengkap');
    }

    const key = await getKeyByDate(tanggal_surat, klasifikasi);
    // decrypt key
    const decryptedKey = await decryptSandidata(key);

    const [result] = await db.execute(
      `INSERT INTO surat (nomor_surat, tahun, perihal, tanggal_surat, klasifikasi, pengirim, penandatangan, nama_dokumen)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [nomor_surat, tahun, perihal, tanggal_surat, klasifikasi, pengirim, penandatangan || null, nama_dokumen]
    );
    const id = result.insertId;

    // Encrypt via layanan kripto
    const form = new FormData();
    form.append('file', fs.createReadStream(file.path));
    form.append('key', decryptedKey);
    form.append('aad', String(id));

    const resp = await cryptoApi.post('/encrypt', form, {
      headers: form.getHeaders(),
      responseType: 'stream'
    });

    const encFile = `${Date.now()}-${file.originalname}.enc`;
    const encPath = path.join(UPLOADS_DIR, encFile);

    await new Promise((resolve, reject) => {
      const ws = fs.createWriteStream(encPath);
      resp.data.pipe(ws);
      resp.data.on('end', resolve);
      resp.data.on('error', reject);
    });

    // bersihkan file asli
    fs.existsSync(file.path) && fs.unlinkSync(file.path);

    // simpan path relatif
    await db.execute('UPDATE surat SET file_path = ? WHERE id = ?', [path.join('uploads', encFile), id]);
    return ok(res);
  } catch (err) {
    console.error('Upload surat keluar error:', err);
    return fail(res, 500, err.message || 'Gagal upload surat keluar');
  }
});

// Decrypt by ID (stream PDF)
app.get('/decrypt/:id', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM surat WHERE id = ?', [req.params.id]);
    if (!rows.length) return fail(res, 404, 'Surat tidak ditemukan');

    const surat = rows[0];
    const key = await getKeyByDate(surat.tanggal_surat, surat.klasifikasi);
    // decrypt key
    const decryptedKey = await decryptSandidata(key);

    // file path relatif disimpan sebagai 'uploads/<file>'
    const fullPath = path.join(__dirname, surat.file_path);
    if (!fs.existsSync(fullPath)) return fail(res, 404, 'File terenkripsi tidak ditemukan');

    const form = new FormData();
    form.append('file', fs.createReadStream(fullPath));
    form.append('key', decryptedKey);
    form.append('aad', String(surat.id));

    const response = await cryptoApi.post('/decrypt', form, {
      headers: form.getHeaders(),
      responseType: 'stream'
    });

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="${(surat.nama_dokumen || 'dokumen')}.pdf"`);
    response.data.pipe(res);
  } catch (err) {
    console.error('Decrypt error:', err);
    return fail(res, 500, 'Gagal dekripsi');
  }
});

// Data surat keluar
app.get('/data-surat-keluar', async (req, res) => {
  try {
    const pengirim = req.query.pengirim;
    if (!pengirim) return fail(res, 400, 'Parameter pengirim dibutuhkan');

    const [rows] = await db.execute(`
      SELECT 
        sk.*, 
        sk.penandatangan AS penandatangan,
        COUNT(ps.id) AS jumlah_penerima,
        SUM(ps.status = 'diterima') AS jumlah_diterima,
        GROUP_CONCAT(DISTINCT CASE WHEN ps.penerima != 'alice' THEN ps.penerima END SEPARATOR ', ') AS daftar_penerima,
        (
          SELECT ps2.pengirim
          FROM pengiriman_surat ps2
          WHERE ps2.surat_id = sk.id AND ps2.penerima = 'alice'
          LIMIT 1
        ) AS pengirim_ke_alice,
        (
          SELECT GROUP_CONCAT(CONCAT(ps2.pengirim, ': ', ps2.catatan) SEPARATOR ', ')
          FROM pengiriman_surat ps2
          WHERE ps2.surat_id = sk.id AND ps2.penerima = 'alice'
        ) AS catatan_ke_alice,
        sk.status AS status_surat
      FROM surat sk
      LEFT JOIN pengiriman_surat ps ON ps.surat_id = sk.id
      WHERE sk.pengirim = ?
      GROUP BY sk.id
    `, [pengirim]);

    return ok(res, rows);
  } catch (err) {
    console.error('Data surat keluar error:', err);
    return fail(res, 500, 'Gagal mengambil data surat keluar');
  }
});

// Kirim surat
app.post('/kirim-surat', async (req, res) => {
  try {
    const { suratId, pengirim, penerima, catatan } = req.body || {};
    if (!Array.isArray(penerima)) return fail(res, 400, 'Penerima harus berupa array');
    if (!pengirim || typeof pengirim !== 'string') return fail(res, 400, 'Pengirim tidak valid');
    if (!suratId || isNaN(Number(suratId))) return fail(res, 400, 'ID surat tidak valid');

    const semuaUsername = [pengirim, ...penerima];
    const placeholders = semuaUsername.map(() => '?').join(', ');

    const [rows] = await db.execute(
      `SELECT username FROM users WHERE username IN (${placeholders})`,
      semuaUsername
    );

    const validUsernames = rows.map(r => r.username);
    const usernameTidakValid = semuaUsername.filter(u => !validUsernames.includes(u));
    if (usernameTidakValid.length > 0) {
      return fail(res, 400, `Username tidak ditemukan: ${usernameTidakValid.join(', ')}`);
    }

    const [[pengirimInfo]] = await db.execute(
      'SELECT opd, jabatan FROM users WHERE username = ?',
      [pengirim]
    );

    const [[suratInfo]] = await db.execute(
      'SELECT pengirim FROM surat WHERE id = ?',
      [suratId]
    );
    const pengirimSurat = suratInfo && suratInfo.pengirim;

    await Promise.all(penerima.map(async (user) => {
      let isFormal = false;

      const [[penerimaInfo]] = await db.execute(
        'SELECT opd, jabatan FROM users WHERE username = ?',
        [user]
      );

      const sameOPD   = pengirimInfo.opd === penerimaInfo.opd;
      const pengirimTU = (pengirimInfo.jabatan || '').toLowerCase().includes('tu');
      const penerimaTU = (penerimaInfo.jabatan || '').toLowerCase().includes('tu');

      if (sameOPD && pengirim === pengirimSurat) {
        isFormal = true;
      } else if (sameOPD && user === pengirimSurat) {
        isFormal = false;
      } else if (sameOPD && user !== pengirimSurat) {
        isFormal = true;
      } else if (!sameOPD && pengirimTU && penerimaTU) {
        isFormal = true;
      } else {
        isFormal = false;
      }

      await db.execute(
        'INSERT INTO pengiriman_surat (surat_id, pengirim, penerima, catatan, is_formal) VALUES (?, ?, ?, ?, ?)',
        [suratId, pengirim, user, catatan || null, isFormal]
      );
    }));

    return ok(res);
  } catch (err) {
    console.error('Kirim surat error:', err);
    return fail(res, 500, 'Terjadi kesalahan server');
  }
});

// Surat masuk (hanya entri formal terbaru per surat)
app.get('/surat-masuk', async (req, res) => {
  try {
    const user = req.query.user;
    if (!user) return fail(res, 400, 'Parameter user dibutuhkan');

    const [rows] = await db.execute(`
      SELECT 
        ps.id AS pengiriman_id,
        ps.status AS status_pengiriman,
        ps.catatan,
        sk.*,
        sk.penandatangan,
        ps.pengirim,
        ps.waktu_kirim
      FROM pengiriman_surat ps
      JOIN surat sk ON ps.surat_id = sk.id
      JOIN (
        SELECT MAX(id) AS max_id
        FROM pengiriman_surat
        WHERE penerima = ?
          AND is_formal = TRUE
        GROUP BY surat_id
      ) latest ON ps.id = latest.max_id
      ORDER BY ps.waktu_kirim DESC
    `, [user]);

    return ok(res, rows);
  } catch (err) {
    console.error('Surat masuk error:', err);
    return fail(res, 500, 'Gagal mengambil surat masuk');
  }
});

// Detail surat + riwayat yang difilter OPD
app.get('/detail-surat', async (req, res) => {
  const id = req.query.id;
  const username = req.query.user;

  if (!id || !username) return fail(res, 400, 'ID atau user tidak disediakan');

  try {
    const [[surat]] = await db.execute('SELECT * FROM surat WHERE id = ?', [id]);
    if (!surat) return fail(res, 404, 'Surat tidak ditemukan');

    const [[currentUser]] = await db.execute('SELECT opd FROM users WHERE username = ?', [username]);
    const userOPD = currentUser && currentUser.opd;
    if (!userOPD) return fail(res, 403, 'Pengguna tidak ditemukan atau tidak memiliki OPD');

    const [riwayatAll] = await db.execute(`
      SELECT ps.pengirim, ps.penerima, ps.catatan, ps.status, ps.waktu_kirim, u.opd AS opd_pengirim
      FROM pengiriman_surat ps
      JOIN users u ON ps.pengirim = u.username
      WHERE ps.surat_id = ?
      ORDER BY ps.waktu_kirim ASC
    `, [id]);

    const filteredRiwayat = riwayatAll.filter(r => r.opd_pengirim === userOPD);
    return ok(res, { surat, riwayat: filteredRiwayat });
  } catch (err) {
    console.error('Gagal ambil detail surat:', err);
    return fail(res, 500, 'Gagal mengambil data');
  }
});

// Terima/tolak surat (update status semua entri surat_id)
app.post('/terima-surat', async (req, res) => {
  const connection = await db.getConnection();
  try {
    const { id, status } = req.body || {};
    if (!id || typeof status !== 'string') {
      await connection.release();
      return fail(res, 400, 'Parameter tidak lengkap');
    }

    await connection.beginTransaction();

    const [[pengiriman]] = await connection.execute(
      'SELECT surat_id FROM pengiriman_surat WHERE id = ?',
      [id]
    );

    if (!pengiriman) {
      await connection.rollback();
      await connection.release();
      return fail(res, 404, 'Data tidak ditemukan');
    }

    const surat_id = pengiriman.surat_id;

    const [result] = await connection.execute(
      'UPDATE pengiriman_surat SET status = ? WHERE id = ?',
      [status, id]
    );

    if (result.affectedRows === 0) {
      await connection.rollback();
      await connection.release();
      return fail(res, 404, 'Data tidak ditemukan');
    }

    await connection.execute(
      'UPDATE pengiriman_surat SET status = ? WHERE surat_id = ?',
      [status, surat_id]
    );

    await connection.commit();
    return ok(res);
  } catch (err) {
    await connection.rollback();
    console.error('Update status error:', err);
    return fail(res, 500, 'Gagal memperbarui status');
  } finally {
    connection.release();
  }
});

// Daftar penerima (OPD sama, role user, kecuali pengirim)
app.get('/penerima-surat', async (req, res) => {
  const pengirim = req.query.username;
  if (!pengirim) return fail(res, 400, 'Parameter username dibutuhkan');

  try {
    const [[pengirimData]] = await db.execute('SELECT opd FROM users WHERE username = ?', [pengirim]);
    if (!pengirimData) return fail(res, 404, 'Pengirim tidak ditemukan');

    const [users] = await db.execute(`
      SELECT username, jabatan, opd
      FROM users
      WHERE username != ? AND role = 'user' AND opd = ?
      ORDER BY jabatan
    `, [pengirim, pengirimData.opd]);

    return ok(res, users);
  } catch (err) {
    console.error(err);
    return fail(res, 500, 'Gagal mengambil penerima surat');
  }
});

// User info
app.get('/user-info', async (req, res) => {
  try {
    const { username } = req.query;
    if (!username) return fail(res, 400, 'Username dibutuhkan');

    const [rows] = await db.execute(
      'SELECT jabatan, opd FROM users WHERE username = ?',
      [username]
    );

    if (!rows.length) return fail(res, 404, 'User tidak ditemukan');
    return ok(res, rows[0]);
  } catch (err) {
    console.error('User info error:', err);
    return fail(res, 500, 'Internal server error');
  }
});

// Get surat by id
app.get('/get-surat/:id', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM surat WHERE id = ?', [req.params.id]);
    if (!rows.length) return fail(res, 404, 'Surat tidak ditemukan');
    return ok(res, { surat: rows[0] });
  } catch (err) {
    console.error('Get surat error:', err);
    return fail(res, 500, 'Gagal mengambil surat');
  }
});

// Edit surat keluar (+opsional ganti file)
app.post('/edit-surat-keluar', upload.single('file'), async (req, res) => {
  try {
    const { id, nomor_surat, tahun, perihal, tanggal_surat, klasifikasi, pengirim, nama_dokumen } = req.body || {};
    if (!id) {
      req.file && fs.existsSync(req.file.path) && fs.unlinkSync(req.file.path);
      return fail(res, 400, 'ID surat wajib');
    }

    const [oldDataRows] = await db.execute('SELECT file_path FROM surat WHERE id = ?', [id]);
    if (!oldDataRows.length) {
      req.file && fs.existsSync(req.file.path) && fs.unlinkSync(req.file.path);
      return fail(res, 404, 'Surat tidak ditemukan');
    }

    let storedRelPath = oldDataRows[0].file_path;
    const fileBaru = req.file;

    if (fileBaru) {
      const key = await getKeyByDate(tanggal_surat, klasifikasi);
      // decrypt key
      const decryptedKey = await decryptSandidata(key);
      const form = new FormData();
      form.append('file', fs.createReadStream(fileBaru.path));
      form.append('key', decryptedKey);
      form.append('aad', String(id));

      const resp = await cryptoApi.post('/encrypt', form, {
        headers: form.getHeaders(),
        responseType: 'stream'
      });

      const encFile = `${Date.now()}-${fileBaru.originalname}.enc`;
      const encPath = path.join(UPLOADS_DIR, encFile);

      await new Promise((resolve, reject) => {
        const ws = fs.createWriteStream(encPath);
        resp.data.pipe(ws);
        resp.data.on('end', resolve);
        resp.data.on('error', reject);
      });

      // hapus file sementara
      fs.existsSync(fileBaru.path) && fs.unlinkSync(fileBaru.path);

      // hapus file lama (abs path)
      if (storedRelPath) {
        const oldAbs = path.isAbsolute(storedRelPath) ? storedRelPath : path.join(__dirname, storedRelPath);
        fs.existsSync(oldAbs) && fs.unlinkSync(oldAbs);
      }

      storedRelPath = path.join('uploads', encFile);
    }

    await db.execute(
      `UPDATE surat
       SET nomor_surat=?, tahun=?, perihal=?, tanggal_surat=?, klasifikasi=?, pengirim=?, nama_dokumen=?, file_path=?
       WHERE id=?`,
      [nomor_surat, tahun, perihal, tanggal_surat, klasifikasi, pengirim, nama_dokumen, storedRelPath, id]
    );

    return ok(res);
  } catch (err) {
    console.error('Edit surat error:', err);
    return fail(res, 500, 'Gagal update surat');
  }
});

// Daftar OPD tujuan (beda OPD, petugas TU)
app.get('/daftar-opd-tujuan', async (req, res) => {
  const pengirim = req.query.username;
  if (!pengirim) return fail(res, 400, 'Parameter username dibutuhkan');

  try {
    const [[pengirimData]] = await db.execute('SELECT opd FROM users WHERE username = ?', [pengirim]);
    if (!pengirimData) return fail(res, 404, 'Pengirim tidak ditemukan');

    const [rows] = await db.execute(`
      SELECT DISTINCT opd, username AS petugas_tu
      FROM users
      WHERE opd != ? AND jabatan = 'Petugas TU' AND role = 'user'
    `, [pengirimData.opd]);

    const hasil = rows.map(row => ({
      opd: row.opd,
      petugas_tu: row.petugas_tu,
      nama_opd: `OPD ${row.opd}` // placeholder, sesuaikan jika ada master OPD
    }));

    return ok(res, hasil);
  } catch (err) {
    console.error('Gagal ambil daftar OPD:', err);
    return fail(res, 500, 'Gagal mengambil daftar OPD');
  }
});


// Penandatanganan RSA: decrypt -> sign (embedSignatureToPDF) -> encrypt (streaming)
app.post('/tandatangan', async (req, res) => {
  // util kecil untuk tunggu writeStream selesai dengan 'finish'
  const pipeToFile = (readable, filePath) =>
    new Promise((resolve, reject) => {
      const ws = fs.createWriteStream(filePath);
      readable.pipe(ws);
      ws.on('finish', resolve);
      ws.on('error', reject);
      readable.on('error', reject);
    });

  let decryptedPath, signedPath;
  try {
    const { surat_id, username, passphrase } = req.body || {};
    if (!surat_id || !username || typeof passphrase !== 'string') {
      return fail(res, 400, 'Parameter tidak lengkap');
    }

    // Ambil metadata surat
    const [[surat]] = await db.execute('SELECT * FROM surat WHERE id = ?', [surat_id]);
    if (!surat) return fail(res, 404, 'Surat tidak ditemukan');

    const encPath = path.join(__dirname, surat.file_path);
    if (!fs.existsSync(encPath)) return fail(res, 404, 'File terenkripsi tidak ditemukan');

    // Ambil kunci enkripsi sesuai kebijakan waktu/klasifikasi
    const key = await getKeyByDate(surat.tanggal_surat, surat.klasifikasi);
    // decrypt key
    const decryptedKey = await decryptSandidata(key);

    // Lokasi file sementara
    const tmpDir = os.tmpdir();
    decryptedPath = path.join(tmpDir, `decrypted-${Date.now()}.pdf`);
    signedPath    = path.join(tmpDir, `signed-${Date.now()}.pdf`);

    // 1) Dekripsi (streaming -> file)
    const decryptForm = new FormData();
    decryptForm.append('file', fs.createReadStream(encPath));
    decryptForm.append('key', decryptedKey);
    decryptForm.append('aad', String(surat.id));

    const decryptResp = await cryptoApi.post('/decrypt', decryptForm, {
      headers: decryptForm.getHeaders(),
      responseType: 'stream'
    });
    await pipeToFile(decryptResp.data, decryptedPath);

    // 2) Sign-after-save + append container (embedSignatureToPDF)
    const keyPath = path.join(SIGN_CERTS_DIR, `${username}.key.pem`);
    if (!fs.existsSync(keyPath)) {
      fs.existsSync(decryptedPath) && fs.unlinkSync(decryptedPath);
      return fail(res, 404, 'Private key penandatangan tidak ditemukan');
    }
    const privateKeyPem = fs.readFileSync(keyPath, 'utf8');

    await embedSignatureToPDF(
      decryptedPath,
      signedPath,
      { username, privateKeyPem, passphrase } // passphrase boleh '' jika key tidak terenkripsi
    );

    // 3) Enkripsi ulang hasil tanda tangan (streaming -> file)
    const encryptForm = new FormData();
    encryptForm.append('file', fs.createReadStream(signedPath));
    encryptForm.append('key', decryptedKey);
    encryptForm.append('aad', String(surat.id));

    const encryptResp = await cryptoApi.post('/encrypt', encryptForm, {
      headers: encryptForm.getHeaders(),
      responseType: 'stream'
    });

    // Nama file hasil: <nama_lama>_signed.pdf.enc
    const originalName = path.basename(surat.file_path).replace(/\.pdf\.enc$/i, '').replace(/\.enc$/i, '');
    const signedEncryptedFile = `${originalName}_signed.pdf.enc`;
    const finalPath = path.join(UPLOADS_DIR, signedEncryptedFile);

    await pipeToFile(encryptResp.data, finalPath);

    // 4) Bersih-bersih file sementara & hapus file lama terenkripsi
    fs.existsSync(decryptedPath) && fs.unlinkSync(decryptedPath);
    fs.existsSync(signedPath) && fs.unlinkSync(signedPath);
    fs.existsSync(encPath) && fs.unlinkSync(encPath);

    // 5) Update DB simpan path relatif
    const relativePath = path.join('uploads', signedEncryptedFile);
    await db.execute('UPDATE surat SET file_path = ? WHERE id = ?', [relativePath, surat_id]);

    return ok(res);
  } catch (err) {
    console.error('Tandatangan RSA error:', err);
    return fail(res, 500, err.message || 'Gagal tanda tangan');
  } finally {
    // fallback cleanup jika error sebelum langkah bersih-bersih
    try { decryptedPath && fs.existsSync(decryptedPath) && fs.unlinkSync(decryptedPath); } catch {}
    try { signedPath && fs.existsSync(signedPath) && fs.unlinkSync(signedPath); } catch {}
  }
});


app.get('/penandatangan', async (req, res) => {
  const username = req.query.username;
  if (!username) {
    return res.status(400).json({ success: false, message: 'Username dibutuhkan' });
  }

  try {
    // Ambil OPD dari user yang login
    const [[userData]] = await db.execute(
      'SELECT opd FROM users WHERE username = ?',
      [username]
    );

    if (!userData) {
      return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
    }

    // Ambil daftar penandatangan di OPD yang sama
    const [penandatangan] = await db.execute(
      'SELECT username, jabatan FROM users WHERE opd = ? AND jabatan IN ("Kepala", "Sekretaris", "Atasan")',
      [userData.opd]
    );

    res.json({
      success: true,
      data: penandatangan
    });
  } catch (err) {
    console.error('Gagal ambil penandatangan:', err);
    res.status(500).json({ success: false, message: 'Terjadi kesalahan server' });
  }
});

function extractSignatureContainer(pdfBuffer) {
  const endIdx = pdfBuffer.lastIndexOf(SIG_END);
  const beginIdx = pdfBuffer.lastIndexOf(SIG_BEGIN);
  if (endIdx === -1 || beginIdx === -1 || beginIdx > endIdx) return null;

  const metaB64Buf = pdfBuffer.slice(beginIdx + SIG_BEGIN.length, endIdx);
  const metaJson = Buffer.from(String(metaB64Buf).trim(), 'base64').toString('utf8');
  const meta = JSON.parse(metaJson);

  return {
    meta,
    signedBytes: pdfBuffer.slice(0, beginIdx), // konten yang ditandatangani
  };
}

function loadPublicKeyForUser(username) {
  const crtPath = path.join(SIGN_CERTS_DIR, `${username}.crt.pem`);
  const pubPath = path.join(SIGN_CERTS_DIR, `${username}.pub.pem`);

  if (fs.existsSync(crtPath)) {
    const certPem = fs.readFileSync(crtPath, 'utf8');
    const x509 = new crypto.X509Certificate(certPem);
    return { publicKeyPem: x509.publicKey, certPem, certPath: crtPath };
  }
  if (fs.existsSync(pubPath)) {
    return { publicKeyPem: fs.readFileSync(pubPath, 'utf8'), certPem: null, certPath: null };
  }
  throw new Error(`Sertifikat/public key untuk user ${username} tidak ditemukan`);
}

async function verifySignedPDF(pdfPath) {
  const buf = fs.readFileSync(pdfPath);
  if (!buf.slice(0, 5).toString().startsWith('%PDF-')) {
    return { ok: false, code: 'NOT_PDF', message: 'Bukan PDF' };
  }

  const container = extractSignatureContainer(buf);
  if (!container) return { ok: false, code: 'NO_SIGNATURE', message: 'Kontainer tanda tangan tidak ditemukan' };

  const { meta, signedBytes } = container;
  if (meta.alg !== 'RSA-SHA256') {
    return { ok: false, code: 'ALG_UNSUPPORTED', message: `Algoritma ${meta.alg} tidak didukung` };
  }

  // Konsistensi hash dokumen
  const calcHash = sha256Hex(signedBytes);
  if (meta.doc_sha256 && meta.doc_sha256 !== calcHash) {
    return { ok: false, code: 'DOC_TAMPERED', message: 'Konten dokumen berubah (hash tidak cocok)' };
  }

  // Verifikasi signature
  const { publicKeyPem, certPem, certPath } = loadPublicKeyForUser(meta.signer);
  const signature = Buffer.from(meta.signature_b64, 'base64');
  const ok = crypto.verify('sha256', signedBytes, { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_PADDING }, signature);

  // Info sertifikat dasar
  let certInfo = { hasCert: false };
  if (certPem) {
    const x = new crypto.X509Certificate(certPem);
    const now = new Date();
    const notBefore = new Date(x.validFrom);
    const notAfter = new Date(x.validTo);
    certInfo = {
      hasCert: true,
      subject: x.subject,
      notBefore: notBefore.toISOString(),
      notAfter: notAfter.toISOString(),
      validNow: now >= notBefore && now <= notAfter
    };
  }

  return {
    ok,
    code: ok ? 'VALID' : 'INVALID_SIGNATURE',
    message: ok ? 'Tanda tangan valid' : 'Tanda tangan tidak valid',
    signer: meta.signer,
    signed_at: meta.ts || null,
    algorithm: meta.alg,
    document: { sha256_signed_part: calcHash, bytes_signed: signedBytes.length, bytes_total: buf.length },
    certificate: certInfo,
  };
}

// ===== Endpoint: /verifikasi =====
app.post('/verifikasi', async (req, res) => {
  try {
    const { surat_id } = req.body || {};
    if (!surat_id) return fail(res, 400, 'Parameter tidak lengkap');

    const [[surat]] = await db.execute('SELECT * FROM surat WHERE id = ?', [surat_id]);
    if (!surat) return fail(res, 404, 'Surat tidak ditemukan');

    const encAbsPath = path.join(__dirname, surat.file_path);
    if (!fs.existsSync(encAbsPath)) return fail(res, 404, 'File tidak ditemukan');

    const key = await getKeyByDate(surat.tanggal_surat, surat.klasifikasi);
    //decrypt key
    const decryptedKey = await decryptSandidata(key);

    const tmpDir = os.tmpdir();
    const rnd = (crypto.randomUUID?.() || Math.random().toString(36).slice(2));
    const decryptedPath = path.join(tmpDir, `verify-${Date.now()}-${rnd}.pdf`);

    if (surat.file_path.toLowerCase().endsWith('.enc')) {
      const form = new FormData();
      form.append('file', fs.createReadStream(encAbsPath));
      form.append('key', decryptedKey);
      form.append('aad', String(surat.id));

      const resp = await cryptoApi.post('/decrypt', form, {
        headers: form.getHeaders(),
        responseType: 'stream'
      });

      // FIX utama: tunggu 'finish', bukan 'end'
      await pipeline(resp.data, fs.createWriteStream(decryptedPath));
    } else {
      fs.copyFileSync(encAbsPath, decryptedPath);
    }

    const verdict = await verifySignedPDF(decryptedPath);

    try { fs.unlinkSync(decryptedPath); } catch {}
    return res.status(200).json({ ok: verdict.ok, ...verdict });
  } catch (err) {
    console.error('Verifikasi tanda tangan error:', err);
    return fail(res, 500, err.message || 'Gagal verifikasi');
  }
});



app.use('/web/api', api);

// ---------- START SERVER ----------
app.listen(PORT, () => {
  console.log(`[${NODE_ENV}] Server running at http://localhost:${PORT}`);
});
