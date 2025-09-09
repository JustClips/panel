// Rolbox Command Server - Upgraded with MySQL, File Uploads, Turnstile, & Luarmor Integration
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const multer = require('multer');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
// Safe import for express-rate-limit (won't crash if missing)
let rateLimit;
try {
  rateLimit = require('express-rate-limit');
} catch (e) {
  console.warn('[WARN] express-rate-limit not installed — rate limiting disabled.');
  rateLimit = () => (req, res, next) => next();
}
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_TIMEOUT_MS = 30000; // 30s
const SNAPSHOT_INTERVAL_MS = 5 * 60 * 1000; // 5 min

// --- SERVE FRONTEND STATIC FILES ---
app.use(express.static('public'));

// --- TRUST PROXY FOR RAILWAY ---
app.set('trust proxy', 1);

// --- SECURITY & CORE MIDDLEWARE ---
app.use(helmet());

// --- CORS ---
const allowedOrigins = [
  'https://eps1llon.win',
  'https://www.eps1llon.win'
];

const corsOptions = {
  origin: function (origin, callback) {
    try {
      // Allow same-origin / curl / mobile apps
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      console.error(`Blocking origin: ${origin}`);
      return callback(new Error('Not allowed by CORS'));
    } catch (e) {
      console.error('CORS check error:', e);
      return callback(null, true);
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// --- PARSER MIDDLEWARE (ORDER IS IMPORTANT) ---
// Must be before routes and verifyTurnstile middleware
app.use(bodyParser.json({ limit: '100kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '100kb' }));

// --- ADDITIONAL SECURITY MIDDLEWARE ---
const validateRequest = (req, res, next) => {
  const userAgent = req.headers['user-agent'] || '';
  const suspiciousAgents = ['bot', 'crawler', 'scanner'];
  if (suspiciousAgents.some(a => userAgent.toLowerCase().includes(a))) {
    console.warn(`Suspicious user agent detected: ${userAgent} from ${req.ip}`);
  }
  const contentLength = parseInt(req.headers['content-length'] || 0, 10);
  if (contentLength > 10 * 1024 * 1024) {
    return res.status(413).json({ error: 'Payload too large' });
  }
  next();
};
app.use(validateRequest);

// --- CONFIGURATION ENDPOINT ---
// This endpoint serves public, non-secret environment variables to the frontend.
app.get('/api/config', (req, res) => {
  // IMPORTANT: ONLY include public keys here. NEVER expose secrets like JWT_SECRET, DB passwords, etc.
  if (!process.env.TURNSTILE_SITE_KEY) {
    console.error("FATAL: TURNSTILE_SITE_KEY is not set in the environment variables.");
    return res.status(500).json({ error: "Server is misconfigured. Cannot provide Turnstile key." });
  }

  res.json({
    // This is the PUBLIC key for the Cloudflare Turnstile widget
    turnstileSiteKey: process.env.TURNSTILE_SITE_KEY
  });
});

// --- FILE UPLOAD & STATIC SERVING ---
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
app.use('/uploads', express.static('uploads'));

const storage = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, uploadDir); },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype !== 'image/png' || !file.originalname.match(/\.(png)$/i)) {
      return cb(new Error('Only .png files are allowed!'), false);
    }
    cb(null, true);
  }
});

// In-memory stores
let clients = new Map();
let pendingCommands = new Map();

// --- MYSQL DATABASE SETUP ---
const dbPool = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 60000,
  connectTimeout: 60000,
});

// --- DATABASE INITIALIZATION ---
async function initializeDatabase() {
  try {
    const connection = await dbPool.getConnection();
    console.log('Successfully connected to MySQL database.');

    await connection.query(`CREATE TABLE IF NOT EXISTS connections (
      id INT AUTO_INCREMENT PRIMARY KEY,
      client_id VARCHAR(255) NOT NULL,
      username VARCHAR(255) NOT NULL,
      user_id BIGINT,
      game_name VARCHAR(255),
      server_info VARCHAR(255),
      player_count INT,
      connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`);

    await connection.query(`CREATE TABLE IF NOT EXISTS commands (
      id INT AUTO_INCREMENT PRIMARY KEY,
      command_type VARCHAR(50) NOT NULL,
      content TEXT,
      executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`);

    await connection.query(`CREATE TABLE IF NOT EXISTS player_snapshots (
      id INT AUTO_INCREMENT PRIMARY KEY,
      player_count INT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`);

    await connection.query(`CREATE TABLE IF NOT EXISTS adminusers (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      role ENUM('admin','seller','buyer') NOT NULL DEFAULT 'buyer',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`);

    await connection.query(`CREATE TABLE IF NOT EXISTS key_redemptions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      redeemed_by_admin VARCHAR(255) NOT NULL,
      discord_user_id VARCHAR(255) NOT NULL,
      generated_key VARCHAR(255) NOT NULL,
      screenshot_filename VARCHAR(255),
      redeemed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`);

    await connection.query(`CREATE TABLE IF NOT EXISTS tickets (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      status ENUM('awaiting', 'processing', 'completed') DEFAULT 'awaiting',
      license_key VARCHAR(255),
      payment_method VARCHAR(50),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES adminusers(id)
    );`);

    await connection.query(`CREATE TABLE IF NOT EXISTS ticket_messages (
      id INT AUTO_INCREMENT PRIMARY KEY,
      ticket_id INT NOT NULL,
      sender ENUM('user', 'seller') NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE
    );`);

    await connection.query(`CREATE TABLE IF NOT EXISTS user_locations (
      id INT AUTO_INCREMENT PRIMARY KEY,
      client_id VARCHAR(255) NOT NULL,
      username VARCHAR(255) NOT NULL,
      city VARCHAR(255),
      country VARCHAR(255),
      latitude DECIMAL(10, 8),
      longitude DECIMAL(11, 8),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_client_id (client_id),
      INDEX idx_country (country)
    );`);

    await connection.query(`CREATE TABLE IF NOT EXISTS executor_stats (
      id INT AUTO_INCREMENT PRIMARY KEY,
      client_id VARCHAR(255) NOT NULL,
      username VARCHAR(255) NOT NULL,
      executor_name VARCHAR(255),
      executor_version VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      INDEX idx_executor (executor_name)
    );`);

    // default admins
    const [adminUsers] = await connection.query("SELECT COUNT(*) as count FROM adminusers WHERE role = 'admin'");
    if (adminUsers[0].count === 0) {
      console.log('Creating default admin users...');
      const hashedVupxy = await bcrypt.hash('vupxydev', 10);
      const hashedMegamind = await bcrypt.hash('megaminddev', 10);
      await connection.query(
        "INSERT INTO adminusers (username, password_hash, role) VALUES (?, ?, 'admin'), (?, ?, 'admin')",
        ['vupxy', hashedVupxy, 'megamind', hashedMegamind]
      );
    }

    // default sellers
    const sellerUsers = [
      { username: 'Vandelz', password: 'Vandelzseller1' },
      { username: 'zuse35', password: 'zuse35seller1' },
      { username: 'Duzin', password: 'Duzinseller1' },
      { username: 'swiftkey', password: 'swiftkeyseller1' }
    ];

    for (const user of sellerUsers) {
      const [existingUser] = await connection.query("SELECT COUNT(*) as count FROM adminusers WHERE username = ?", [user.username]);
      if (existingUser[0].count === 0) {
        console.log(`Creating seller user: ${user.username}...`);
        const hashedPassword = await bcrypt.hash(user.password, 10);
        await connection.query(
          "INSERT INTO adminusers (username, password_hash, role) VALUES (?, ?, 'seller')",
          [user.username, hashedPassword]
        );
        console.log(`User ${user.username} created.`);
      }
    }

    connection.release();
    console.log('Database initialization complete.');
  } catch (error) {
    console.error('!!! DATABASE INITIALIZATION FAILED !!!', error);
    process.exit(1);
  }
}

// --- AUTH MIDDLEWARE ---
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized: No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Forbidden: Invalid token' });
    req.user = user;
    next();
  });
};

const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
    }
    next();
  };
};

const requireAdmin = requireRole(['admin']);
const requireSeller = requireRole(['seller', 'admin']);
const requireBuyer = requireRole(['buyer', 'admin']);
const requireAnyRole = requireRole(['admin', 'seller', 'buyer']);

// --- TURNSTILE VERIFY MIDDLEWARE (Interactive challenge) ---
// Expects token via body['cf-turnstile-response'] (standard).
// Accepts token via body['turnstileToken'], headers, or query for flexibility (though frontend primarily uses body).
// Bypass in dev with TURNSTILE_BYPASS=1
async function verifyTurnstile(req, res, next) {
  try {
    if (process.env.TURNSTILE_BYPASS === '1') {
      console.warn('[Turnstile] Bypass enabled via TURNSTILE_BYPASS=1');
      return next();
    }

    // --- Focus on the standard location first ---
    let token = req.body['cf-turnstile-response'];

    // --- Fallbacks (less common for standard frontend setup) ---
    if (!token) {
      token =
        req.body['turnstileToken'] ||
        req.headers['cf-turnstile-response'] ||
        req.headers['x-turnstile-token'] ||
        req.query['cf-turnstile-response'] ||
        req.query['turnstileToken'];
    }

    if (!process.env.TURNSTILE_SECRET) {
      console.error('TURNSTILE_SECRET not set in environment variables.');
      return res.status(500).json({ message: 'Server misconfiguration: Turnstile secret key missing.' });
    }
    if (!token) {
      console.warn(`Turnstile verification failed for ${req.ip}: No token provided in request.`);
      return res.status(400).json({ message: 'Challenge required. Please complete the Turnstile verification.' });
    }

    const form = new URLSearchParams();
    form.append('secret', process.env.TURNSTILE_SECRET);
    form.append('response', token);
    // It's good practice to include the user's IP
    if (req.ip) form.append('remoteip', req.ip);

    const verifyRes = await axios.post(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      form.toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 }
    );

    // --- More detailed logging for debugging ---
    if (verifyRes.data && verifyRes.data.success === true) {
      console.log(`Turnstile verification successful for IP: ${req.ip}`);
      return next();
    } else {
      console.warn(`Turnstile verification failed for IP: ${req.ip}. Response data:`, verifyRes.data);
      // Check for specific error codes if needed, but a generic message is usually fine for the client
      // const errorCodes = verifyRes.data['error-codes'] || [];
      // if (errorCodes.includes('timeout-or-duplicate')) { ... }
      return res.status(403).json({ message: 'Turnstile verification failed. Please try again.' });
    }

  } catch (e) {
    console.error('Turnstile verification error for IP:', req.ip, 'Error:', e.message);
    // Differentiate between network errors and other issues if possible
    if (e.code === 'ECONNABORTED' || e.code === 'ENOTFOUND') {
       return res.status(503).json({ message: 'Unable to verify challenge (network issue). Please try again.' });
    }
    return res.status(503).json({ message: 'Challenge verification temporarily unavailable. Try again.' });
  }
}


// --- RATE LIMITERS ---
const registerLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many registration attempts. Try again later.' }
});

// --- INPUT VALIDATION MIDDLEWARE ---
const validateTicketCreation = [
  body('paymentMethod')
    .trim()
    .notEmpty().withMessage('Payment method is required.')
    .isIn(['PayPal', 'Crypto', 'Credit Card', 'Bank Transfer', 'Google Pay', 'Apple Pay', 'CashApp', 'Gag Pets', 'Secret Brainrots'])
    .withMessage('Invalid payment method selected.')
    .isLength({ min: 2, max: 50 })
    .withMessage('Payment method must be between 2 and 50 characters.')
];

const validateTicketMessage = [
  body('message')
    .trim()
    .notEmpty().withMessage('Message cannot be empty.')
    .isLength({ min: 1, max: 1000 })
    .withMessage('Message must be between 1 and 1000 characters.')
    .escape()
];

const validateDiscordId = [
  body('discordUsername')
    .trim()
    .isLength({ min: 17, max: 20 })
    .isNumeric()
    .withMessage('Invalid Discord ID format')
];

const validateKeyRedemption = [
  ...validateDiscordId,
];

// --- AUTHENTICATION ENDPOINTS ---
// ORDER: rate limit -> Turnstile -> handler
app.post('/register', registerLimiter, verifyTurnstile, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ message: 'Invalid input types.' });
  }
  if (username.length < 3 || username.length > 30) {
    return res.status(400).json({ message: 'Username must be between 3 and 30 characters.' });
  }
  if (password.length < 6 || password.length > 100) {
    return res.status(400).json({ message: 'Password must be between 6 and 100 characters.' });
  }
  if (password.toLowerCase() === username.toLowerCase()) {
    return res.status(400).json({ message: 'Password cannot be similar to username.' });
  }

  try {
    const [existingUsers] = await dbPool.query("SELECT id FROM adminusers WHERE username = ?", [username]);
    if (existingUsers.length > 0) {
      return res.status(409).json({ message: 'Username already taken.' });
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    await dbPool.query("INSERT INTO adminusers (username, password_hash, role) VALUES (?, ?, 'buyer')", [username, hashedPassword]);
    res.status(201).json({ success: true, message: 'User created successfully.' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || !process.env.JWT_SECRET) {
    return res.status(400).json({ message: 'Invalid request or server config error.' });
  }
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ message: 'Invalid input types.' });
  }
  try {
    const [rows] = await dbPool.query("SELECT * FROM adminusers WHERE username = ?", [username]);
    if (rows.length === 0) {
      await new Promise(resolve => setTimeout(resolve, 1000)); // Brute force mitigation
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });
    const payload = { id: user.id, username: user.username, role: user.role };
    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: '8h',
      issuer: 'aperture-hub'
    });
    res.json({ success: true, token, username: user.username, role: user.role });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/verify-token', verifyToken, (req, res) => {
  res.json({ user: req.user });
});

app.post('/logout', (req, res) => {
  res.json({ success: true });
});

// --- TICKET ENDPOINTS ---
app.get('/tickets/my', verifyToken, requireAnyRole, async (req, res) => {
  try {
    const [tickets] = await dbPool.query(
      `SELECT t.*, u.username as buyer_name
       FROM tickets t
       JOIN adminusers u ON t.user_id = u.id
       WHERE t.user_id = ?
       ORDER BY t.updated_at DESC`,
      [req.user.id]
    );
    for (let ticket of tickets) {
      const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [ticket.id]);
      ticket.messages = messages;
    }
    res.json(tickets);
  } catch (error) {
    console.error('Error fetching user tickets:', error);
    res.status(500).json({ message: 'Failed to fetch tickets' });
  }
});

app.get('/tickets/all', verifyToken, requireSeller, async (req, res) => {
  try {
    const [tickets] = await dbPool.query(
      `SELECT t.*, u.username as buyer_name
       FROM tickets t
       JOIN adminusers u ON t.user_id = u.id
       ORDER BY t.updated_at DESC`
    );
    for (let ticket of tickets) {
      const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [ticket.id]);
      ticket.messages = messages;
    }
    res.json(tickets);
  } catch (error) {
    console.error('Error fetching all tickets:', error);
    res.status(500).json({ message: 'Failed to fetch all tickets' });
  }
});

app.post('/tickets',
  verifyToken,
  requireBuyer,
  validateTicketCreation,
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation failed', errors: errors.array().map(e => e.msg) });
    }
    const { paymentMethod } = req.body;
    try {
      const [existingTickets] = await dbPool.query(
        "SELECT id FROM tickets WHERE user_id = ? AND status != 'completed'",
        [req.user.id]
      );
      if (existingTickets.length > 0) {
        return res.status(400).json({ message: 'You already have an open ticket. Please wait for it to be processed.' });
      }
      const [recentTickets] = await dbPool.query(
        "SELECT COUNT(*) as count FROM tickets WHERE user_id = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
        [req.user.id]
      );
      if (recentTickets[0].count > 5) {
        return res.status(429).json({ message: 'Too many tickets created recently. Please try again later.' });
      }
      const licenseKey = 'PENDING-' + Date.now();
      const [result] = await dbPool.query(
        "INSERT INTO tickets (user_id, license_key, payment_method, status) VALUES (?, ?, ?, 'awaiting')",
        [req.user.id, licenseKey, paymentMethod]
      );
      const ticketId = result.insertId;
      const message = `Welcome! A seller will be with you shortly to help you purchase with ${paymentMethod}.`;
      await dbPool.query("INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, ?, ?)", [ticketId, 'seller', message]);
      const [tickets] = await dbPool.query(
        `SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`,
        [ticketId]
      );
      const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [ticketId]);
      const ticket = tickets[0];
      ticket.messages = messages;
      res.status(201).json(ticket);
    } catch (error) {
      console.error('Error creating ticket:', error);
      res.status(500).json({ message: 'Failed to create ticket' });
    }
  }
);

app.post('/tickets/:id/messages',
  verifyToken,
  requireAnyRole,
  validateTicketMessage,
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: 'Validation failed', errors: errors.array().map(e => e.msg) });
    }
    const { id } = req.params;
    const { message } = req.body;
    if (!id || isNaN(id)) {
      return res.status(400).json({ message: 'Invalid ticket ID' });
    }
    try {
      const [tickets] = await dbPool.query("SELECT * FROM tickets WHERE id = ?", [id]);
      if (tickets.length === 0) {
        return res.status(404).json({ message: 'Ticket not found.' });
      }
      const ticket = tickets[0];
      if (req.user.role === 'buyer' && ticket.user_id !== req.user.id) {
        return res.status(403).json({ message: 'You can only send messages to your own tickets.' });
      }
      const [recentMessages] = await dbPool.query(
        "SELECT COUNT(*) as count FROM ticket_messages WHERE ticket_id = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 MINUTE)",
        [id]
      );
      if (recentMessages[0].count > 5) {
        return res.status(429).json({ message: 'Too many messages sent recently. Please slow down.' });
      }
      const senderType = (ticket.user_id === req.user.id) ? 'user' : 'seller';
      await dbPool.query("INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, ?, ?)", [id, senderType, message]);
      if (ticket.status === 'awaiting') {
        await dbPool.query("UPDATE tickets SET status = 'processing', updated_at = CURRENT_TIMESTAMP WHERE id = ?", [id]);
      } else {
        await dbPool.query("UPDATE tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", [id]);
      }
      const [updatedTickets] = await dbPool.query(
        `SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`,
        [id]
      );
      const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [id]);
      const updatedTicket = updatedTickets[0];
      updatedTicket.messages = messages;
      res.json(updatedTicket);
    } catch (error) {
      console.error('Error adding message:', error);
      res.status(500).json({ message: 'Failed to add message' });
    }
  }
);

app.post('/api/tickets/:id/close',
  verifyToken,
  requireSeller,
  async (req, res) => {
    const { id } = req.params;
    if (!id || isNaN(id)) {
      return res.status(400).json({ message: 'Invalid ticket ID' });
    }
    try {
      const [tickets] = await dbPool.query("SELECT * FROM tickets WHERE id = ?", [id]);
      if (tickets.length === 0) {
        return res.status(404).json({ message: 'Ticket not found.' });
      }
      await dbPool.query("UPDATE tickets SET status = 'completed', updated_at = CURRENT_TIMESTAMP WHERE id = ?", [id]);
      const [updatedTickets] = await dbPool.query(
        `SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`,
        [id]
      );
      const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [id]);
      const updatedTicket = updatedTickets[0];
      updatedTicket.messages = messages;
      res.json(updatedTicket);
    } catch (error) {
      console.error('Error closing ticket:', error);
      res.status(500).json({ message: 'Failed to close ticket' });
    }
  }
);

app.delete('/api/tickets/:id',
  verifyToken,
  requireSeller,
  async (req, res) => {
    const { id } = req.params;
    if (!id || isNaN(id)) {
      return res.status(400).json({ message: 'Invalid ticket ID' });
    }
    try {
      const [tickets] = await dbPool.query("SELECT * FROM tickets WHERE id = ?", [id]);
      if (tickets.length === 0) {
        return res.status(404).json({ message: 'Ticket not found.' });
      }
      await dbPool.query("DELETE FROM tickets WHERE id = ?", [id]);
      res.json({ success: true, message: `Ticket #${id} has been permanently deleted.` });
    } catch (error) {
      console.error('Error deleting ticket:', error);
      res.status(500).json({ message: 'Failed to delete ticket' });
    }
  }
);

// --- GAME CLIENT ENDPOINTS ---
app.post('/connect', async (req, res) => {
  const {
    id, username, gameName, serverInfo, playerCount, userId,
    city, country, executorName, executorVersion
  } = req.body;
  if (!id || !username) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }
  if (typeof id !== 'string' || typeof username !== 'string') {
    return res.status(400).json({ error: 'Invalid field types.' });
  }
  if (id.length > 255 || username.length > 255) {
    return res.status(400).json({ error: 'Field values too long.' });
  }
  if (playerCount !== undefined && (isNaN(playerCount) || playerCount < 0 || playerCount > 1000000)) {
    return res.status(400).json({ error: 'Invalid player count.' });
  }
  clients.set(id, {
    id, username, gameName, serverInfo, playerCount, userId,
    city, country, executorName, executorVersion,
    connectedAt: new Date(), lastSeen: Date.now()
  });
  if (!pendingCommands.has(id)) pendingCommands.set(id, []);
  console.log(`[CONNECT] Client registered: ${username} (ID: ${id})`);
  try {
    await dbPool.query(
      "INSERT INTO connections (client_id, username, user_id, game_name, server_info, player_count) VALUES (?, ?, ?, ?, ?, ?)",
      [id, username, userId, gameName, serverInfo, playerCount]
    );
    if (city && country) {
      let lat = null, lon = null;
      try {
        const geoResponse = await axios.get(`http://ip-api.com/json/${city},${country}`);
        if (geoResponse.data && geoResponse.data.lat && geoResponse.data.lon) {
          lat = geoResponse.data.lat; lon = geoResponse.data.lon;
        }
      } catch (geoError) { console.warn('Geolocation lookup failed:', geoError.message); }
      await dbPool.query(
        "INSERT INTO user_locations (client_id, username, city, country, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?)",
        [id, username, city, country, lat, lon]
      );
    }
    if (executorName) {
      await dbPool.query(
        "INSERT INTO executor_stats (client_id, username, executor_name, executor_version) VALUES (?, ?, ?, ?)",
        [id, username, executorName, executorVersion || 'Unknown']
      );
    }
  } catch (error) {
    console.error(`[DB] Failed to log connection for ${username}:`, error.message);
  }
  res.json({ message: 'Successfully registered.' });
});

app.post('/heartbeat', async (req, res) => {
  const {
    id, username, gameName, serverInfo, playerCount, userId,
    city, country, executorName, executorVersion
  } = req.body;
  if (!id || !clients.has(id)) {
    return res.status(404).json({ error: 'Client not registered.' });
  }
  const client = clients.get(id);
  client.lastSeen = Date.now();
  client.gameName = gameName || client.gameName;
  client.serverInfo = serverInfo || client.serverInfo;
  client.playerCount = playerCount !== undefined ? playerCount : client.playerCount;
  client.userId = userId || client.userId;
  client.city = city || client.city;
  client.country = country || client.country;
  client.executorName = executorName || client.executorName;
  client.executorVersion = executorVersion || client.executorVersion;

  if (city && country && (city !== client.city || country !== client.country)) {
    try {
      let lat = null, lon = null;
      const geoResponse = await axios.get(`http://ip-api.com/json/${city},${country}`);
      if (geoResponse.data && geoResponse.data.lat && geoResponse.data.lon) {
        lat = geoResponse.data.lat; lon = geoResponse.data.lon;
      }
      await dbPool.query(
        "INSERT INTO user_locations (client_id, username, city, country, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?)",
        [id, username, city, country, lat, lon]
      );
    } catch (geoError) {
      console.warn('Geolocation lookup failed:', geoError.message);
    }
  }
  if (executorName && executorName !== client.executorName) {
    await dbPool.query(
      "INSERT INTO executor_stats (client_id, username, executor_name, executor_version) VALUES (?, ?, ?, ?)",
      [id, username, executorName, executorVersion || 'Unknown']
    );
  }
  res.json({ message: 'Heartbeat received.' });
});

app.post('/poll', (req, res) => {
  const { id } = req.body;
  if (!id || !clients.has(id)) return res.status(404).json({ error: 'Client not registered.' });
  clients.get(id).lastSeen = Date.now();
  const commands = pendingCommands.get(id) || [];
  pendingCommands.set(id, []);
  res.json({ commands });
});

// --- PROTECTED ADMIN ENDPOINTS ---
app.get('/api/clients', verifyToken, requireAnyRole, (req, res) => {
  res.json({ count: clients.size, clients: Array.from(clients.values()) });
});

app.post('/broadcast', verifyToken, requireAdmin, async (req, res) => {
  const { command } = req.body;
  if (!command) return res.status(400).json({ error: 'Missing "command"' });
  if (typeof command !== 'string' && typeof command !== 'object') {
    return res.status(400).json({ error: 'Invalid command format' });
  }
  const commandSize = JSON.stringify(command).length;
  if (commandSize > 10000) {
    return res.status(400).json({ error: 'Command too large' });
  }
  const commandObj = { type: 'execute', payload: command };
  let successCount = 0;
  clients.forEach((c, id) => {
    pendingCommands.get(id)?.push(commandObj);
    successCount++;
  });
  try {
    const commandType = typeof command === 'string' ? 'lua_script' : 'json_action';
    await dbPool.query("INSERT INTO commands (command_type, content) VALUES (?, ?)", [commandType, JSON.stringify(command)]);
  } catch (error) {
    console.error('[DB] Failed to log broadcast command:', error.message);
  }
  res.json({ message: `Command broadcasted to ${successCount}/${clients.size} clients.` });
});

app.post('/api/command/targeted', verifyToken, requireAdmin, (req, res) => {
  const { clientIds, command } = req.body;
  if (!Array.isArray(clientIds) || !command)
    return res.status(400).json({ error: 'Missing "clientIds" array or "command".' });
  if (clientIds.length > 100) {
    return res.status(400).json({ error: 'Too many clients specified' });
  }
  if (typeof command !== 'string' && typeof command !== 'object') {
    return res.status(400).json({ error: 'Invalid command format' });
  }
  const commandObj = { type: 'execute', payload: command };
  let successCount = 0;
  clientIds.forEach(id => {
    if (clients.has(id) && pendingCommands.has(id)) {
      pendingCommands.get(id).push(commandObj);
      successCount++;
    }
  });
  res.json({ message: `Command sent to ${successCount}/${clientIds.length} selected clients.` });
});

app.post('/kick', verifyToken, requireAdmin, (req, res) => {
  const { clientId } = req.body;
  const client = clients.get(clientId);
  if (!client) return res.status(404).json({ error: 'Client not found.' });
  pendingCommands.get(clientId)?.push({ type: 'kick' });
  setTimeout(() => {
    clients.delete(clientId);
    pendingCommands.delete(clientId);
  }, 5000);
  res.json({ message: `Client ${client.username} kicked.` });
});

app.post('/api/seller/redeem',
  verifyToken,
  requireSeller,
  upload.single('screenshot'),
  validateKeyRedemption,
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', errors: errors.array().map(e => e.msg) });
    }
    const { discordUsername: discordUserId } = req.body;
    const adminUsername = req.user.username;
    if (!discordUserId) return res.status(400).json({ error: 'Discord User ID is required.' });
    if (!req.file) return res.status(400).json({ error: 'Screenshot file is required.' });
    if (!process.env.LUARMOR_API_KEY || !process.env.LUARMOR_PROJECT_ID) {
      return res.status(500).json({ error: 'Luarmor API is not configured on the server.' });
    }
    if (req.file.size > 5 * 1024 * 1024) {
      if (req.file.path) fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'File too large. Maximum 5MB allowed.' });
    }
    const url = `https://api.luarmor.net/v3/projects/${process.env.LUARMOR_PROJECT_ID}/users`;
    const headers = { Authorization: process.env.LUARMOR_API_KEY, 'Content-Type': 'application/json' };
    const payload = { discord_id: discordUserId, note: `Redeemed by ${adminUsername} on ${new Date().toLocaleDateString()}` };
    try {
      const luarmorResponse = await axios.post(url, payload, { headers, timeout: 10000 });
      const data = luarmorResponse.data;
      if (data.success && data.user_key) {
        const newKey = data.user_key;
        await dbPool.query(
          "INSERT INTO key_redemptions (redeemed_by_admin, discord_user_id, generated_key, screenshot_filename) VALUES (?, ?, ?, ?)",
          [adminUsername, discordUserId, newKey, req.file.filename]
        );
        res.json({ success: true, message: `Key successfully generated and linked to ${discordUserId}.`, generatedKey: newKey });
      } else {
        if (req.file && req.file.path) fs.unlinkSync(req.file.path);
        res.status(400).json({ success: false, error: `Luarmor API Error: ${data.message || 'Unknown error.'}` });
      }
    } catch (error) {
      if (req.file && req.file.path) fs.unlinkSync(req.file.path);
      console.error('Luarmor API request failed:', error.response ? error.response.data : error.message);
      if (error.response) {
        if (error.response.status === 429) {
          return res.status(429).json({ error: 'Rate limit exceeded with key service. Please try again later.' });
        }
        if (error.response.status >= 500) {
          return res.status(503).json({ error: 'Key service temporarily unavailable. Please try again later.' });
        }
      }
      res.status(500).json({ error: 'An internal error occurred while communicating with the key service.' });
    }
  }
);

// --- ANALYTICS & LOGS ENDPOINTS ---
async function getAggregatedData(tableName, dateColumn, valueColumn, period, aggregationFn = 'COUNT') {
  let interval, groupByFormat;
  switch (period) {
    case 'daily':
      interval = '24 HOUR';
      groupByFormat = '%Y-%m-%d %H:00:00';
      break;
    case 'weekly':
      interval = '7 DAY';
      groupByFormat = '%Y-%m-%d';
      break;
    case 'monthly':
    default:
      interval = '30 DAY';
      groupByFormat = '%Y-%m-%d';
      break;
  }
  const query = `
    SELECT DATE_FORMAT(${dateColumn}, ?) AS date, ${aggregationFn}(${valueColumn}) AS count
    FROM ${tableName}
    WHERE ${dateColumn} >= NOW() - INTERVAL ${interval}
    GROUP BY date ORDER BY date ASC;
  `;
  const [rows] = await dbPool.query(query, [groupByFormat]);
  return rows;
}

app.get('/api/executions', verifyToken, requireAnyRole, async (req, res) => {
  try {
    const data = await getAggregatedData('connections', 'connected_at', 'id', req.query.period, 'COUNT');
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve connection statistics.' });
  }
});

app.get('/api/player-stats', verifyToken, requireAnyRole, async (req, res) => {
  try {
    const data = await getAggregatedData('player_snapshots', 'created_at', 'player_count', req.query.period, 'MAX');
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve player statistics.' });
  }
});

app.get('/api/seller/keys-sold', verifyToken, requireSeller, async (req, res) => {
  try {
    const data = await getAggregatedData('key_redemptions', 'redeemed_at', 'id', req.query.period, 'COUNT');
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve key redemption statistics.' });
  }
});

app.get('/api/seller/sales-log', verifyToken, requireSeller, async (req, res) => {
  try {
    const [rows] = await dbPool.query("SELECT * FROM key_redemptions ORDER BY redeemed_at DESC LIMIT 1000");
  res.json(rows);
  } catch (error) {
    console.error('Failed to retrieve sales log:', error);
    res.status(500).json({ error: 'Failed to retrieve sales log.' });
  }
});

// --- 3D EARTH VISUALIZATION ENDPOINTS ---
app.get('/api/locations', verifyToken, requireAnyRole, async (req, res) => {
  try {
    const [locations] = await dbPool.query(`
      SELECT DISTINCT city, country, latitude, longitude, COUNT(*) as user_count
      FROM user_locations
      WHERE latitude IS NOT NULL AND longitude IS NOT NULL
      GROUP BY city, country, latitude, longitude
      ORDER BY user_count DESC
      LIMIT 1000
    `);
    res.json(locations);
  } catch (error) {
    console.error('Error fetching locations:', error);
    res.status(500).json({ error: 'Failed to fetch location data' });
  }
});

app.get('/api/executor-stats', verifyToken, requireAnyRole, async (req, res) => {
  try {
    const [executors] = await dbPool.query(`
      SELECT executor_name, COUNT(*) as usage_count, COUNT(DISTINCT username) as unique_users
      FROM executor_stats
      WHERE executor_name IS NOT NULL
      GROUP BY executor_name
      ORDER BY usage_count DESC
    `);
    res.json(executors);
  } catch (error) {
    console.error('Error fetching executor stats:', error);
    res.status(500).json({ error: 'Failed to fetch executor statistics' });
  }
});

app.get('/api/country-stats', verifyToken, requireAnyRole, async (req, res) => {
  try {
    const [countries] = await dbPool.query(`
      SELECT country, COUNT(*) as user_count
      FROM user_locations
      WHERE country IS NOT NULL
      GROUP BY country
      ORDER BY user_count DESC
    `);
    res.json(countries);
  } catch (error) {
    console.error('Error fetching country stats:', error);
    res.status(500).json({ error: 'Failed to fetch country statistics' });
  }
});

// --- HEALTH CHECK ---
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// --- UTILITY INTERVALS ---
setInterval(() => {
  const now = Date.now();
  clients.forEach((client, id) => {
    if (now - client.lastSeen > CLIENT_TIMEOUT_MS) {
      clients.delete(id);
      pendingCommands.delete(id);
      console.log(`[TIMEOUT] Kicked inactive client: ${client.username} (ID: ${id})`);
    }
  });
}, 5000);

setInterval(async () => {
  if (clients.size > 0) {
    try {
      await dbPool.query("INSERT INTO player_snapshots (player_count) VALUES (?)", [clients.size]);
    } catch (error) {
      console.error('[DB] Failed to log player snapshot:', error.message);
    }
  }
}, SNAPSHOT_INTERVAL_MS);

// --- GLOBAL ERROR HANDLING ---
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large. Maximum 5MB allowed.' });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({ error: 'Too many files uploaded.' });
    }
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  }
  if (err.name === 'ValidationError') {
    return res.status(400).json({ error: err.message });
  }
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ error: 'Invalid token' });
  }
  if (err.code === 'ERR_ERL_UNEXPECTED_X_FORWARDED_FOR') {
    console.warn('X-Forwarded-For header detected with trust proxy enabled');
    return next();
  }
  res.status(500).json({ error: 'Internal server error' });
});

// --- START SERVER ---
async function startServer() {
  await initializeDatabase();
  app.listen(PORT, () => console.log(`Aperture Command Server running on port ${PORT}`));
}
startServer();
