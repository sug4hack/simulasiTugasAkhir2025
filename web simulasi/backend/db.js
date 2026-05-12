// ===== backend/db.js =====
const mysql = require('mysql2/promise');
require('dotenv').config();

// Helper untuk require ENV
const reqEnv = (key) => {
  const val = process.env[key];
  if (!val) {
    console.error(`Missing required env: ${key}`);
    process.exit(1);
  }
  return val;
};

const pool = mysql.createPool({
  host: reqEnv('DB_HOST'),
  port: parseInt(process.env.DB_PORT || '3306', 10),
  user: reqEnv('DB_USER'),
  password: reqEnv('DB_PASS'),
  database: reqEnv('DB_NAME'),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

pool.getConnection()
  .then(conn => {
    console.log('✅ Database connected');
    conn.release();
  })
  .catch(err => {
    console.error('❌ Database connection failed:', err.message);
    process.exit(1);
  });

module.exports = pool;
