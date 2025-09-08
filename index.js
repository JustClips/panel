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
const fs = require('fs/promises');
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

// TICKETS
app.get('/tickets/my', verifyToken, apiLimiter, async (req, res, next) => {
  try {
    const [tickets] = await dbPool.query(
      `SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.user_id = ? ORDER BY t.updated_at DESC`,
      [req.user.id]
    );
    for (const ticket of tickets) {
      const [messages] = await dbPool.query('SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC', [ticket.id]);
      ticket.messages = messages;
    }
    res.json(tickets);
  } catch (err) {
    next(err);
  }
});

app.get('/tickets/all', verifyToken, verifyRole('seller', 'admin'), apiLimiter, async (req, res, next) => {
  try {
    const [tickets] = await dbPool.query(
      `SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id ORDER BY t.updated_at DESC`
    );
    for (const ticket of tickets) {
      const [messages] = await dbPool.query('SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC', [ticket.id]);
      ticket.messages = messages;
    }
    res.json(tickets);
  } catch (err) {
    next(err);
  }
});

app.post(
  '/tickets',
  verifyToken,
  csrfProtection,
  body('paymentMethod').isLength({ min: 2, max: 50 }).trim().escape(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        addStrike(req.ip);
        return res.status(400).json({ errors: errors.array() });
      }
      const { paymentMethod } = req.body;
      const userId = req.user.id;
      const [existing] = await dbPool.query('SELECT id FROM tickets WHERE user_id = ?', [userId]);
      if (existing.length > 0) {
        addStrike(req.ip, 2);
        return res.status(409).json({ message: 'Only one ticket allowed per user.' });
      }
      const licenseKey = `PENDING-${nanoid(16)}`;
      const [result] = await dbPool.query(
        'INSERT INTO tickets (user_id, license_key, payment_method, status) VALUES (?, ?, ?, "awaiting")',
        [userId, licenseKey, paymentMethod]
      );
      const ticketId = result.insertId;
      const welcomeMsg = `Welcome! A seller will assist you shortly with payment method: ${paymentMethod}.`;
      await dbPool.query('INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, "seller", ?)', [ticketId, welcomeMsg]);
      const [tickets] = await dbPool.query(
        `SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`,
        [ticketId]
      );
      const [messages] = await dbPool.query('SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC', [ticketId]);
      tickets[0].messages = messages;
      res.status(201).json(tickets[0]);
    } catch (err) {
      next(err);
    }
  }
);

app.post(
  '/tickets/:id/messages',
  verifyToken,
  apiLimiter,
  csrfProtection,
  body('message').isLength({ min: 1, max: 2000 }).trim().escape(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        addStrike(req.ip);
        return res.status(400).json({ errors: errors.array() });
      }
      const { id } = req.params;
      const { message } = req.body;
      const [tickets] = await dbPool.query('SELECT * FROM tickets WHERE id = ?', [id]);
      if (tickets.length === 0) return res.status(404).json({ message: 'Ticket not found.' });
      const ticket = tickets[0];
      if (req.user.role === 'buyer' && ticket.user_id !== req.user.id) {
        return res.status(403).json({ message: 'Forbidden: You do not own this ticket.' });
      }
      const senderType = ['seller', 'admin'].includes(req.user.role) ? 'seller' : 'user';
      await dbPool.query('INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, ?, ?)', [id, senderType, message]);
      if (ticket.status === 'awaiting' && senderType === 'seller') {
        await dbPool.query('UPDATE tickets SET status = "processing", updated_at = CURRENT_TIMESTAMP WHERE id = ?', [id]);
      } else {
        await dbPool.query('UPDATE tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?', [id]);
      }
      const [updatedTickets] = await dbPool.query(
        `SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`,
        [id]
      );
      const [messages] = await dbPool.query('SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC', [id]);
      updatedTickets[0].messages = messages;
      res.json(updatedTickets[0]);
    } catch (err) {
      next(err);
    }
  }
);

app.post(
  '/api/tickets/:id/close',
  verifyToken,
  verifyRole('seller', 'admin'),
  actionLimiter,
  csrfProtection,
  async (req, res, next) => {
    try {
      const { id } = req.params;
      const [tickets] = await dbPool.query('SELECT * FROM tickets WHERE id = ?', [id]);
      if (tickets.length === 0) return res.status(404).json({ message: 'Ticket not found.' });
      await dbPool.query('UPDATE tickets SET status = "completed", updated_at = CURRENT_TIMESTAMP WHERE id = ?', [id]);
      const [updatedTickets] = await dbPool.query(
        `SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`,
        [id]
      );
      const [messages] = await dbPool.query('SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC', [id]);
      updatedTickets[0].messages = messages;
      res.json(updatedTickets[0]);
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  '/api/tickets/:id',
  verifyToken,
  verifyRole('seller', 'admin'),
  actionLimiter,
  csrfProtection,
  async (req, res, next) => {
    try {
      const { id } = req.params;
      const [tickets] = await dbPool.query('SELECT * FROM tickets WHERE id = ?', [id]);
      if (tickets.length === 0) return res.status(404).json({ message: 'Ticket not found.' });
      await dbPool.query('DELETE FROM tickets WHERE id = ?', [id]);
      res.json({ success: true, message: `Ticket #${id} deleted.` });
    } catch (err) {
      next(err);
    }
  }
);

// --- ADMIN/SELLER ENDPOINTS ---

app.get('/api/clients', verifyToken, verifyRole('seller', 'admin'), apiLimiter, (req, res) => {
  res.json({ count: clients.size, clients: Array.from(clients.values()) });
});

app.post(
  '/broadcast',
  verifyToken,
  verifyRole('admin'),
  actionLimiter,
  csrfProtection,
  async (req, res, next) => {
    try {
      const { command } = req.body;
      if (!command) return res.status(400).json({ error: 'Missing command' });
      const commandObj = { type: 'execute', payload: command };
      let successCount = 0;
      clients.forEach((_, id) => {
        if (!pendingCommands.has(id)) pendingCommands.set(id, []);
        pendingCommands.get(id).push(commandObj);
        successCount++;
      });
      const commandType = typeof command === 'string' ? 'lua_script' : 'json_action';
      await dbPool.query('INSERT INTO commands (command_type, content, executed_by) VALUES (?, ?, ?)', [
        commandType,
        JSON.stringify(command),
        req.user.username,
      ]);
      res.json({ message: `Command broadcasted to ${successCount}/${clients.size} clients.` });
    } catch (err) {
      next(err);
    }
  }
);

app.post(
  '/kick',
  verifyToken,
  verifyRole('admin'),
  actionLimiter,
  csrfProtection,
  (req, res) => {
    const { clientId } = req.body;
    if (!clientId) return res.status(400).json({ error: 'Missing clientId' });
    const client = clients.get(clientId);
    if (!client) return res.status(404).json({ error: 'Client not found' });
    if (!pendingCommands.has(clientId)) pendingCommands.set(clientId, []);
    pendingCommands.get(clientId).push({ type: 'kick' });
    setTimeout(() => {
      clients.delete(clientId);
      pendingCommands.delete(clientId);
    }, 5000);
    res.json({ message: `Client ${client.username} kicked.` });
  }
);

app.get(
  '/uploads/:filename',
  verifyToken,
  verifyRole('seller', 'admin'),
  async (req, res, next) => {
    try {
      const filename = path.basename(req.params.filename);
      if (filename.includes('..')) return res.status(400).send('Invalid filename');
      const filePath = path.join(UPLOAD_DIR, filename);
      const [records] = await dbPool.query('SELECT id FROM key_redemptions WHERE screenshot_filename = ?', [filename]);
      if (records.length === 0) return res.status(404).json({ message: 'File not found or access denied' });
      res.sendFile(filePath);
    } catch (err) {
      next(err);
    }
  }
);

app.post(
  '/api/seller/redeem',
  verifyToken,
  verifyRole('seller', 'admin'),
  actionLimiter,
  csrfProtection,
  upload.single('screenshot'),
  body('discordUsername').isNumeric().isLength({ min: 17, max: 20 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        addStrike(req.ip);
        return res.status(400).json({ errors: errors.array() });
      }
      if (!req.file) return res.status(400).json({ error: 'Screenshot file is required' });

      const filename = `${nanoid(16)}.png`;
      const filePath = path.join(UPLOAD_DIR, filename);
      await fs.writeFile(filePath, req.file.buffer);

      const discordUserId = req.body.discordUsername;
      const adminUsername = req.user.username;

      const url = `https://api.luarmor.net/v3/projects/${process.env.LUARMOR_PROJECT_ID}/users`;
      const headers = {
        Authorization: process.env.LUARMOR_API_KEY,
        'Content-Type': 'application/json',
      };
      const payload = {
        discord_id: discordUserId,
        note: `Redeemed by ${adminUsername} on ${new Date().toLocaleDateString()}`,
      };

      const response = await axios.post(url, payload, { headers });
      const data = response.data;

      if (data.success && data.user_key) {
        await dbPool.query(
          'INSERT INTO key_redemptions (redeemed_by_admin, discord_user_id, generated_key, screenshot_filename) VALUES (?, ?, ?, ?)',
          [adminUsername, discordUserId, data.user_key, filename]
        );
        return res.json({ success: true, message: `Key generated for ${discordUserId}`, generatedKey: data.user_key });
      } else {
        await fs.unlink(filePath);
        return res.status(400).json({ success: false, error: data.message || 'Luarmor API error' });
      }
    } catch (err) {
      if (req.file) {
        try {
          await fs.unlink(path.join(UPLOAD_DIR, `${nanoid(16)}.png`));
        } catch {}
      }
      next(err);
    }
  }
);

app.get('/api/executions', verifyToken, verifyRole('seller', 'admin'), apiLimiter, async (req, res, next) => {
  try {
    const data = await getAggregatedData('connections', 'connected_at', 'id', req.query.period, 'COUNT');
    res.json(data);
  } catch (err) {
    next(err);
  }
});

app.get('/api/player-stats', verifyToken, verifyRole('seller', 'admin'), apiLimiter, async (req, res, next) => {
  try {
    const data = await getAggregatedData('player_snapshots', 'created_at', 'player_count', req.query.period, 'MAX');
    res.json(data);
  } catch (err) {
    next(err);
  }
});

app.get('/api/seller/keys-sold', verifyToken, verifyRole('seller', 'admin'), apiLimiter, async (req, res, next) => {
  try {
    const data = await getAggregatedData('key_redemptions', 'redeemed_at', 'id', req.query.period, 'COUNT');
    res.json(data);
  } catch (err) {
    next(err);
  }
});

app.get('/api/seller/sales-log', verifyToken, verifyRole('seller', 'admin'), apiLimiter, async (req, res, next) => {
  try {
    const [rows] = await dbPool.query('SELECT * FROM key_redemptions ORDER BY redeemed_at DESC');
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// --- GAME CLIENT ENDPOINTS ---

app.post('/connect', globalLimiter, async (req, res, next) => {
  try {
    const { id, username, gameName, serverInfo, playerCount, userId } = req.body;
    if (!id || !username) return res.status(400).json({ error: 'Missing required fields' });
    clients.set(id, { id, username, gameName, serverInfo, playerCount, userId, connectedAt: new Date(), lastSeen: Date.now() });
    if (!pendingCommands.has(id)) pendingCommands.set(id, []);
    await dbPool.query(
      'INSERT INTO connections (client_id, username, user_id, game_name, server_info, player_count, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [id, username, userId, gameName, serverInfo, playerCount, req.ip]
    );
    res.json({ message: 'Successfully registered' });
  } catch (err) {
    next(err);
  }
});

app.post('/poll', globalLimiter, (req, res) => {
  const { id } = req.body;
  if (!id || !clients.has(id)) return res.status(404).json({ error: 'Client not registered' });
  const client = clients.get(id);
  client.lastSeen = Date.now();
  const commands = pendingCommands.get(id) || [];
  pendingCommands.set(id, []);
  res.json({ commands });
});

// --- BACKGROUND TASKS ---

// Remove inactive clients
setInterval(() => {
  const now = Date.now();
  for (const [id, client] of clients.entries()) {
    if (now - client.lastSeen > CLIENT_TIMEOUT_MS) {
      clients.delete(id);
      pendingCommands.delete(id);
      console.log(`[TIMEOUT] Removed inactive client: ${client.username} (${id})`);
    }
  }
}, 5000);

// Log player snapshots
setInterval(async () => {
  if (clients.size > 0) {
    try {
      await dbPool.query('INSERT INTO player_snapshots (player_count) VALUES (?)', [clients.size]);
    } catch (err) {
      console.error('[DB] Failed to log player snapshot:', err.message);
    }
  }
}, SNAPSHOT_INTERVAL_MS);

// Cleanup expired bans and old strikes
setInterval(() => {
  const now = Date.now();
  for (const [ip, expires] of ipBanList.entries()) {
    if (now > expires) {
      ipBanList.delete(ip);
      console.log(`[SECURITY] Unbanned IP: ${ip}`);
    }
  }
  for (const [ip, record] of strikeTracker.entries()) {
    if (now - record.firstStrikeTimestamp > STRIKE_TIMEFRAME_MS) {
      strikeTracker.delete(ip);
    }
  }
}, 5 * 60 * 1000);

// --- ERROR HANDLING ---
app.use((err, req, res, next) => {
  console.error('[ERROR]', err);
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ message: 'Invalid CSRF token' });
  }
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ message: `File upload error: ${err.message}` });
  }
  res.status(500).json({ message: 'Internal server error', error: err.message });
});

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
