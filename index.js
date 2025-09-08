/**
 * Aperture Command Server - Secure & Modern Rewrite
 * Backend: https://panel-production-23ca.up.railway.app
 * Frontend: https://w1ckllon.com
 */

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const knexLib = require('knex');
const session = require('express-session');
const KnexSessionStore = require('connect-session-knex')(session);
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');
const { body, param, validationResult } = require('express-validator');
const { hash, verify } = require('argon2-browser');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs'); // <-- sync fs functions like existsSync, mkdirSync
const fsp = require('fs/promises'); // <-- async fs functions like writeFile, unlink
const axios = require('axios');
const { nanoid } = require('nanoid');

const app = express();

// --- ENVIRONMENT CHECK ---
const requiredEnv = [
  'JWT_SECRET',
  'SESSION_SECRET',
  'DB_HOST',
  'DB_USER',
  'DB_PASSWORD',
  'DB_DATABASE',
  'LUARMOR_API_KEY',
  'LUARMOR_PROJECT_ID',
];
for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.error(`❌ Missing environment variable: ${key}`);
    process.exit(1);
  }
}

// --- CONSTANTS ---
const PORT = process.env.PORT || 3000;
const CLIENT_TIMEOUT_MS = 15_000;
const SNAPSHOT_INTERVAL_MS = 5 * 60 * 1000;
const STRIKE_LIMIT = 10;
const STRIKE_TIMEFRAME_MS = 15 * 60 * 1000;
const BAN_DURATION_MS = 60 * 60 * 1000;
const UPLOAD_DIR = path.join(__dirname, 'Uploads');

// --- IN-MEMORY TRACKERS ---
const strikeTracker = new Map(); // ip -> { strikes, firstStrikeTimestamp }
const ipBanList = new Map(); // ip -> banExpiresAt
const clients = new Map(); // clientId -> clientData
const pendingCommands = new Map(); // clientId -> [commands]

// --- DATABASE SETUP ---
const knex = knexLib({
  client: 'mysql2',
  connection: {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
  },
});

const dbPool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// --- SESSION STORE ---
const sessionStore = new KnexSessionStore({
  knex,
  tablename: 'sessions',
  createtable: false,
  clearInterval: 60 * 60 * 1000,
});

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 8 * 60 * 60 * 1000,
    },
  })
);

// --- SECURITY MIDDLEWARE ---
app.disable('x-powered-by');
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com'],
        styleSrc: ["'self'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com', "'unsafe-inline'"],
        fontSrc: ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  })
);

// --- CORS ---
const allowedOrigins = ['https://w1ckllon.com', process.env.RAILWAY_STATIC_URL].filter(Boolean);
if (process.env.NODE_ENV !== 'production') {
  allowedOrigins.push('http://localhost:5500', 'http://127.0.0.1:5500');
}
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
      callback(new Error('CORS not allowed'));
    },
    credentials: true,
  })
);

// --- BODY PARSERS ---
app.use(bodyParser.json({ limit: '1mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static('public'));

// --- IP BAN CHECK ---
function addStrike(ip, count = 1) {
  const now = Date.now();
  let record = strikeTracker.get(ip) || { strikes: 0, firstStrikeTimestamp: now };
  if (now - record.firstStrikeTimestamp > STRIKE_TIMEFRAME_MS) {
    record = { strikes: 0, firstStrikeTimestamp: now };
  }
  record.strikes += count;
  strikeTracker.set(ip, record);
  if (record.strikes >= STRIKE_LIMIT) {
    ipBanList.set(ip, now + BAN_DURATION_MS);
    strikeTracker.delete(ip);
    console.warn(`[SECURITY] IP banned: ${ip} for 1 hour`);
  }
}
function checkIpBan(req, res, next) {
  const ip = req.ip;
  const banExpires = ipBanList.get(ip);
  if (banExpires && Date.now() < banExpires) {
    return res.status(403).json({ message: 'Forbidden: Your IP is temporarily banned.' });
  }
  next();
}
app.use(checkIpBan);

// --- RATE LIMITERS ---
app.set('trust proxy', 1);

const createRateLimitHandler = (strikeCount) => (req, res) => {
  addStrike(req.ip, strikeCount);
  res.status(429).json({ message: 'Too many requests. Please try again later.' });
};

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  handler: createRateLimitHandler(1),
});
app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  handler: createRateLimitHandler(3),
});

const actionLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.user?.id || req.ip,
  handler: createRateLimitHandler(2),
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  keyGenerator: (req) => req.user?.id || req.ip,
  handler: createRateLimitHandler(1),
});

// --- CSRF PROTECTION ---
const csrfProtection = csrf({
  value: (req) => req.headers['csrf-token'] || req.headers['x-csrf-token'],
});
app.use((req, res, next) => {
  // Skip CSRF for these endpoints
  if (['/connect', '/poll', '/login', '/register', '/api/csrf-token'].includes(req.path)) return next();
  csrfProtection(req, res, next);
});

// --- UPLOAD SETUP ---
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype !== 'image/png') return cb(new Error('Only PNG files allowed'), false);
    // Check PNG magic bytes
    const magic = file.buffer.slice(0, 8).toString('hex');
    if (magic !== '89504e470d0a1a0a') return cb(new Error('Invalid PNG file'), false);
    cb(null, true);
  },
});

// --- AUTH HELPERS ---
async function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    // Check session exists
    const [sessions] = await dbPool.query('SELECT * FROM sessions WHERE sid = ?', [decoded.sessionId]);
    if (sessions.length === 0) return res.status(401).json({ message: 'Session revoked' });
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
}

function verifyRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Forbidden: insufficient permissions' });
    }
    next();
  };
}

// --- DB INIT & MIGRATIONS ---
async function initializeDatabase() {
  const conn = await dbPool.getConnection();
  try {
    // Sessions table
    await conn.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        sid VARCHAR(255) NOT NULL PRIMARY KEY,
        sess JSON NOT NULL,
        expired DATETIME NOT NULL
      );
    `);

    // Admin users
    await conn.query(`
      CREATE TABLE IF NOT EXISTS adminusers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role ENUM('buyer', 'seller', 'admin') NOT NULL DEFAULT 'buyer',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Connections
    await conn.query(`
      CREATE TABLE IF NOT EXISTS connections (
        id INT AUTO_INCREMENT PRIMARY KEY,
        client_id VARCHAR(255) NOT NULL,
        username VARCHAR(255) NOT NULL,
        user_id BIGINT,
        game_name VARCHAR(255),
        server_info VARCHAR(255),
        player_count INT,
        ip_address VARCHAR(45),
        connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Commands
    await conn.query(`
      CREATE TABLE IF NOT EXISTS commands (
        id INT AUTO_INCREMENT PRIMARY KEY,
        command_type VARCHAR(50) NOT NULL,
        content TEXT,
        executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        executed_by VARCHAR(255)
      );
    `);

    // Player snapshots
    await conn.query(`
      CREATE TABLE IF NOT EXISTS player_snapshots (
        id INT AUTO_INCREMENT PRIMARY KEY,
        player_count INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Key redemptions
    await conn.query(`
      CREATE TABLE IF NOT EXISTS key_redemptions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        redeemed_by_admin VARCHAR(255) NOT NULL,
        discord_user_id VARCHAR(255) NOT NULL,
        generated_key VARCHAR(255) NOT NULL,
        screenshot_filename VARCHAR(255),
        redeemed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Tickets
    await conn.query(`
      CREATE TABLE IF NOT EXISTS tickets (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        status ENUM('awaiting', 'processing', 'completed') DEFAULT 'awaiting',
        license_key VARCHAR(255),
        payment_method VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES adminusers(id)
      );
    `);

    // Ticket messages
    await conn.query(`
      CREATE TABLE IF NOT EXISTS ticket_messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ticket_id INT NOT NULL,
        sender ENUM('user', 'seller') NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE
      );
    `);

    // Seed default users
    const defaultUsers = [
      { username: 'Vandelz', password: 'Vandelzseller1', role: 'seller' },
      { username: 'zuse35', password: 'zuse35seller1', role: 'seller' },
      { username: 'Duzin', password: 'Duzinseller1', role: 'seller' },
      { username: 'swiftkey', password: 'swiftkeyseller1', role: 'seller' },
      { username: 'vupxy', password: 'vupxydev', role: 'admin' },
      { username: 'megamind', password: 'megaminddev', role: 'admin' },
    ];

    for (const user of defaultUsers) {
      const [rows] = await dbPool.query('SELECT * FROM adminusers WHERE username = ?', [user.username]);
      if (rows.length === 0) {
        const hashed = await hash(user.password);
        await dbPool.query('INSERT INTO adminusers (username, password_hash, role) VALUES (?, ?, ?)', [
          user.username,
          hashed,
          user.role,
        ]);
      } else if (rows[0].role !== user.role) {
        await dbPool.query('UPDATE adminusers SET role = ? WHERE username = ?', [user.role, user.username]);
      }
    }
  } finally {
    conn.release();
  }
}

// --- UTILS ---
async function getAggregatedData(table, dateCol, valueCol, period, aggFn = 'COUNT') {
  let interval, groupFormat;
  switch (period) {
    case 'daily':
      interval = '24 HOUR';
      groupFormat = '%Y-%m-%d %H:00:00';
      break;
    case 'weekly':
      interval = '7 DAY';
      groupFormat = '%Y-%m-%d';
      break;
    default:
      interval = '30 DAY';
      groupFormat = '%Y-%m-%d';
  }
  const query = `
    SELECT DATE_FORMAT(${dateCol}, ?) AS date, ${aggFn}(${valueCol}) AS count
    FROM ${table}
    WHERE ${dateCol} >= NOW() - INTERVAL ${interval}
    GROUP BY date
    ORDER BY date ASC
  `;
  const [rows] = await dbPool.query(query, [groupFormat]);
  return rows;
}

// --- ROUTES ---

// CSRF token endpoint
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// REGISTER
app.post(
  '/register',
  authLimiter,
  body('username').isAlphanumeric().isLength({ min: 3, max: 20 }).trim(),
  body('password')
    .isLength({ min: 12 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/)
    .withMessage('Password must contain uppercase, lowercase, number, and special character.'),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        addStrike(req.ip);
        return res.status(400).json({ errors: errors.array() });
      }
      const { username, password } = req.body;
      const [existing] = await dbPool.query('SELECT id FROM adminusers WHERE username = ?', [username]);
      if (existing.length > 0) return res.status(409).json({ message: 'Username already taken.' });
      const hashed = await hash(password);
      await dbPool.query('INSERT INTO adminusers (username, password_hash, role) VALUES (?, ?, "buyer")', [username, hashed]);
      res.status(201).json({ success: true, message: 'User created successfully.' });
    } catch (err) {
      next(err);
    }
  }
);

// LOGIN
app.post('/login', authLimiter, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Invalid request.' });
    const [rows] = await dbPool.query('SELECT * FROM adminusers WHERE username = ?', [username]);
    if (rows.length === 0) {
      addStrike(req.ip);
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const user = rows[0];
    const valid = await verify(user.password_hash, password);
    if (!valid) {
      addStrike(req.ip);
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const payload = { id: user.id, username: user.username, role: user.role, sessionId: req.session.id };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ success: true, token, username: user.username, role: user.role });
  } catch (err) {
    next(err);
  }
});

// LOGOUT
app.post('/logout', verifyToken, csrfProtection, (req, res, next) => {
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('connect.sid');
    res.json({ success: true, message: 'Logged out successfully.' });
  });
});

// VERIFY TOKEN
app.get('/verify-token', verifyToken, (req, res) => {
  res.json({ success: true, user: { id: req.user.id, username: req.user.username, role: req.user.role } });
});

// (Other routes omitted for brevity — keep your existing routes here, unchanged)

// --- START SERVER ---
(async () => {
  try {
    await initializeDatabase();
    app.listen(PORT, () => {
      console.log(`🚀 Aperture Command Server running on port ${PORT}`);
    });
  } catch (err) {
    console.error('[STARTUP ERROR]', err);
    process.exit(1);
  }
})();
