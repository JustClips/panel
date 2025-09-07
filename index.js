// Rolbox Command Server - PARANOID EDITION V2.5 (Syntax Fix)
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2/promise');
const { hash, verify } = require('argon2-browser');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const multer = require('multer');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');
const session = require('express-session');
const KnexSessionStore = require('connect-session-knex')(session);
const knex = require('knex');
const csrf = require('csurf');
const { nanoid } = require('nanoid');
require('dotenv').config();

// --- CRITICAL STARTUP CHECKS ---
if (!process.env.JWT_SECRET || !process.env.SESSION_SECRET) {
    console.error("FATAL ERROR: JWT_SECRET and SESSION_SECRET must be defined in your environment variables. The application cannot start securely.");
    process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_TIMEOUT_MS = 15000;
const SNAPSHOT_INTERVAL_MS = 5 * 60 * 1000;

// --- DYNAMIC IP BAN SYSTEM ---
const strikeTracker = new Map();
const ipBanList = new Map();
const STRIKE_LIMIT = 10;
const STRIKE_TIMEFRAME_MS = 15 * 60 * 1000;
const BAN_DURATION_MS = 60 * 60 * 1000;
function addStrike(ip, count = 1) { const now = Date.now(); let record = strikeTracker.get(ip) || { strikes: 0, firstStrikeTimestamp: now }; if (now - record.firstStrikeTimestamp > STRIKE_TIMEFRAME_MS) { record = { strikes: 0, firstStrikeTimestamp: now }; } record.strikes += count; strikeTracker.set(ip, record); if (record.strikes >= STRIKE_LIMIT) { console.log(`[SECURITY] Banning IP ${ip} for 1 hour due to excessive strikes.`); ipBanList.set(ip, now + BAN_DURATION_MS); strikeTracker.delete(ip); } }
const checkIpBan = (req, res, next) => { const ip = req.ip; const banExpires = ipBanList.get(ip); if (banExpires && Date.now() < banExpires) { return res.status(403).json({ message: "Forbidden: Your IP has been temporarily blocked due to suspicious activity." }); } next(); };
app.use(checkIpBan);

// --- SECURITY & CORE MIDDLEWARE ---
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"], styleSrc: ["'self'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "'unsafe-inline'"], fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"], imgSrc: ["'self'", "data:"], connectSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"], } }, hsts: { maxAge: 31536000, includeSubDomains: true, preload: true } }));
const allowedOrigins = [ 'https://w1ckllon.com', process.env.RAILWAY_STATIC_URL ].filter(Boolean);
if (process.env.NODE_ENV !== 'production') {
    allowedOrigins.push('http://localhost:5500', 'http://127.0.0.1:5500');
}
app.use(cors({ origin: allowedOrigins, credentials: true }));
app.use(bodyParser.json({ limit: '1mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static('public'));

// --- SESSION MANAGEMENT & CSRF PROTECTION ---
const dbKnex = knex({ client: 'mysql2', connection: { host: process.env.DB_HOST, user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_DATABASE }});
const sessionStore = new KnexSessionStore({
    knex: dbKnex,
    tablename: 'sessions',
    createtable: false,
    clearInterval: 1000 * 60 * 60
});
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 8 * 60 * 60 * 1000
    }
}));
const csrfProtection = csrf();
app.use((req, res, next) => { if (['/connect', '/poll'].includes(req.path)) { return next(); } csrfProtection(req, res, next); });

// --- FILE UPLOAD (HARDENED) ---
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) { fs.mkdirSync(uploadDir); }
const storage = multer.memoryStorage();
const upload = multer({ storage: storage, limits: { fileSize: 2 * 1024 * 1024 }, fileFilter: (req, file, cb) => { if (file.mimetype !== 'image/png') { return cb(new Error("File is not a PNG."), false); } const stream = file.stream; stream.on('data', (chunk) => { const PNG_MAGIC_NUMBERS = '89504e470d0a1a0a'; const fileMagicNumbers = chunk.toString('hex', 0, 8); if (fileMagicNumbers !== PNG_MAGIC_NUMBERS) { stream.destroy(); return cb(new Error("Invalid file content. Not a true PNG."), false); } }); stream.on('end', () => cb(null, true)); } });

// --- DATABASE & CLIENTS ---
let clients = new Map();
let pendingCommands = new Map();
const dbPool = mysql.createPool({ host: process.env.DB_HOST, user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_DATABASE, waitForConnections: true, connectionLimit: 10, queueLimit: 0 });

async function initializeDatabase() {
    try {
        const connection = await dbPool.getConnection();
        console.log("Successfully connected to MySQL database.");
        
        // <<< SYNTAX FIX >>> Removed the stray "text" word that was here.

        await connection.query(`CREATE TABLE IF NOT EXISTS sessions (sid VARCHAR(255) NOT NULL PRIMARY KEY, sess JSON NOT NULL, expired DATETIME NOT NULL);`);

        await connection.query(`CREATE TABLE IF NOT EXISTS adminusers (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, role ENUM('buyer', 'seller', 'admin') NOT NULL DEFAULT 'buyer', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        const [roleColumns] = await connection.query("SHOW COLUMNS FROM `adminusers` LIKE 'role'");
        if (roleColumns.length === 0) { console.log("Upgrading 'adminusers' table..."); await connection.query("ALTER TABLE `adminusers` ADD COLUMN `role` ENUM('buyer', 'seller', 'admin') NOT NULL DEFAULT 'buyer' AFTER `password_hash`;"); }
        
        await connection.query(`CREATE TABLE IF NOT EXISTS connections (id INT AUTO_INCREMENT PRIMARY KEY, client_id VARCHAR(255) NOT NULL, username VARCHAR(255) NOT NULL, user_id BIGINT, game_name VARCHAR(255), server_info VARCHAR(255), player_count INT, connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        const [ipColumns] = await connection.query("SHOW COLUMNS FROM `connections` LIKE 'ip_address'");
        if (ipColumns.length === 0) {
            console.log("Upgrading 'connections' table, adding 'ip_address' column...");
            await connection.query("ALTER TABLE `connections` ADD COLUMN `ip_address` VARCHAR(45) NULL AFTER `player_count`;");
        }
        
        await connection.query(`CREATE TABLE IF NOT EXISTS commands (id INT AUTO_INCREMENT PRIMARY KEY, command_type VARCHAR(50) NOT NULL, content TEXT, executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, executed_by VARCHAR(255));`);
        await connection.query(`CREATE TABLE IF NOT EXISTS player_snapshots (id INT AUTO_INCREMENT PRIMARY KEY, player_count INT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS key_redemptions (id INT AUTO_INCREMENT PRIMARY KEY, redeemed_by_admin VARCHAR(255) NOT NULL, discord_user_id VARCHAR(255) NOT NULL, generated_key VARCHAR(255) NOT NULL, screenshot_filename VARCHAR(255), redeemed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS tickets (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, status ENUM('awaiting', 'processing', 'completed') DEFAULT 'awaiting', license_key VARCHAR(255), payment_method VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES adminusers(id));`);
        await connection.query(`CREATE TABLE IF NOT EXISTS ticket_messages (id INT AUTO_INCREMENT PRIMARY KEY, ticket_id INT NOT NULL, sender ENUM('user', 'seller') NOT NULL, message TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE);`);
        
        const allUsers = [ { username: 'Vandelz', password: 'Vandelzseller1', role: 'seller' }, { username: 'zuse35', password: 'zuse35seller1', role: 'seller' }, { username: 'Duzin', password: 'Duzinseller1', role: 'seller' }, { username: 'swiftkey', password: 'swiftkeyseller1', role: 'seller' }, { username: 'vupxy', password: 'vupxydev', role: 'admin' }, { username: 'megamind', password: 'megaminddev', role: 'admin' }];
        for (const user of allUsers) { const [existingUser] = await dbPool.query("SELECT * FROM adminusers WHERE username = ?", [user.username]); if (existingUser.length === 0) { console.log(`Creating user: ${user.username}...`); const hashedPassword = await hash(user.password); await dbPool.query("INSERT INTO adminusers (username, password_hash, role) VALUES (?, ?, ?)", [user.username, hashedPassword, user.role]); } else if (existingUser[0].role !== user.role) { console.log(`Updating role for user: ${user.username}`); await dbPool.query("UPDATE adminusers SET role = ? WHERE username = ?", [user.role, user.username]); } }
        connection.release();
        console.log("Database initialization complete.");
    } catch (error) {
        console.error("!!! DATABASE INITIALIZATION FAILED !!!", error);
        process.exit(1);
    }
}

// --- AUTH MIDDLEWARE ---
const verifyToken = async (req, res, next) => { const authHeader = req.headers['authorization']; const token = authHeader && authHeader.split(' ')[1]; if (!token) return res.status(401).json({ message: 'Unauthorized: No token provided' }); try { const decoded = jwt.verify(token, process.env.JWT_SECRET); const [sessions] = await dbPool.query("SELECT * FROM sessions WHERE sid = ?", [decoded.sessionId]); if (sessions.length === 0) { return res.status(401).json({ message: 'Session has been revoked. Please log in again.' }); } req.user = decoded; next(); } catch (err) { return res.status(403).json({ message: 'Forbidden: Invalid or expired token' }); } };
const verifyRole = (...allowedRoles) => (req, res, next) => { if (!req.user || !allowedRoles.includes(req.user.role)) { return res.status(403).json({ message: 'Forbidden: You do not have permission for this action.' }); } next(); };

// --- RATE LIMITERS ---
app.set('trust proxy', 1);
const createRateLimitHandler = (strikeCount) => (req, res, next) => { addStrike(req.ip, strikeCount); res.status(429).json({ message: "Too many requests. Please try again later." }); };
const globalIpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, handler: createRateLimitHandler(1) });
app.use(globalIpLimiter);
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, handler: createRateLimitHandler(3) });
const actionLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, keyGenerator: (req) => req.user.id, handler: createRateLimitHandler(2) });
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, keyGenerator: (req) => req.user.id, handler: createRateLimitHandler(1) });

// --- ROUTES ---
app.get('/api/csrf-token', (req, res) => { res.json({ csrfToken: req.csrfToken() }); });

app.post('/register', authLimiter, body('username').isLength({ min: 3, max: 20 }).isAlphanumeric().trim(), body('password').isLength({ min: 12 }).withMessage('Password must be at least 12 characters long.').matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/).withMessage('Password must contain uppercase, lowercase, number, and special character.'),
    async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) { addStrike(req.ip); return res.status(400).json({ errors: errors.array() }); }
        const { username, password } = req.body;
        const [existingUsers] = await dbPool.query("SELECT id FROM adminusers WHERE username = ?", [username]);
        if (existingUsers.length > 0) return res.status(409).json({ message: 'Username already taken.' });
        const hashedPassword = await hash(password);
        await dbPool.query("INSERT INTO adminusers (username, password_hash, role) VALUES (?, ?, 'buyer')", [username, hashedPassword]);
        res.status(201).json({ success: true, message: 'User created successfully.' });
    } catch (error) { next(error); }
});

app.post('/login', authLimiter, async (req, res, next) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: 'Invalid request.' });
        const [rows] = await dbPool.query("SELECT * FROM adminusers WHERE username = ?", [username]);
        if (rows.length === 0 || !(await verify(rows[0].password_hash, password))) {
            addStrike(req.ip);
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const user = rows[0];
        const payload = { id: user.id, username: user.username, role: user.role, sessionId: req.session.id };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ success: true, token, username: user.username });
    } catch (error) { next(error); }
});

app.post('/logout', verifyToken, (req, res, next) => { req.session.destroy(err => { if (err) return next(err); res.clearCookie('connect.sid'); res.json({ success: true, message: "Logged out successfully." }); }); });
app.get('/verify-token', verifyToken, (req, res) => { res.json({ success: true, message: 'Token is valid.', user: { id: req.user.id, username: req.user.username, role: req.user.role } }); });

// --- TICKET ENDPOINTS ---
app.get('/tickets/my', verifyToken, apiLimiter, async (req, res, next) => { try { const [tickets] = await dbPool.query( `SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.user_id = ? ORDER BY t.updated_at DESC`, [req.user.id] ); for (let ticket of tickets) { const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [ticket.id]); ticket.messages = messages; } res.json(tickets); } catch(error) { next(error) } });
app.get('/tickets/all', verifyToken, verifyRole('seller', 'admin'), apiLimiter, async (req, res, next) => { try { const [tickets] = await dbPool.query( `SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id ORDER BY t.updated_at DESC` ); for (let ticket of tickets) { const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [ticket.id]); ticket.messages = messages; } res.json(tickets); } catch(error) { next(error) } });
app.post('/tickets', verifyToken, body('paymentMethod').isLength({ min: 2, max: 50 }).trim().escape(),
    async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) { addStrike(req.ip); return res.status(400).json({ errors: errors.array() }); }
        const { paymentMethod } = req.body;
        const userId = req.user.id;
        const [existingTickets] = await dbPool.query("SELECT id FROM tickets WHERE user_id = ?", [userId]);
        if (existingTickets.length > 0) { addStrike(req.ip, 2); return res.status(409).json({ message: "You have already created a support ticket. Only one ticket is allowed per user." }); }
        const licenseKey = `PENDING-${nanoid(16)}`;
        const [result] = await dbPool.query("INSERT INTO tickets (user_id, license_key, payment_method, status) VALUES (?, ?, ?, 'awaiting')", [userId, licenseKey, paymentMethod]);
        const ticketId = result.insertId;
        let message = `Welcome! A seller will be with you shortly to help you purchase with ${paymentMethod}.`;
        await dbPool.query("INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, ?, ?)", [ticketId, 'seller', message]);
        const [tickets] = await dbPool.query(`SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`, [ticketId]);
        const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [ticketId]);
        const ticket = tickets[0];
        ticket.messages = messages;
        res.status(201).json(ticket);
    } catch (error) { next(error); }
});
app.post('/tickets/:id/messages', verifyToken, apiLimiter, body('message').isLength({ min: 1, max: 2000 }).trim().escape(),
    async (req, res, next) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) { addStrike(req.ip); return res.status(400).json({ errors: errors.array() }); }
        const { id } = req.params;
        const { message } = req.body;
        const [tickets] = await dbPool.query("SELECT * FROM tickets WHERE id = ?", [id]);
        if (tickets.length === 0) return res.status(404).json({ message: 'Ticket not found.' });
        const ticket = tickets[0];
        if (req.user.role === 'buyer' && ticket.user_id !== req.user.id) { return res.status(403).json({ message: 'Forbidden: You do not own this ticket.'}); }
        const senderType = ['seller', 'admin'].includes(req.user.role) ? 'seller' : 'user';
        await dbPool.query("INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, ?, ?)", [id, senderType, message]);
        if (ticket.status === 'awaiting' && senderType === 'seller') { await dbPool.query("UPDATE tickets SET status = 'processing', updated_at = CURRENT_TIMESTAMP WHERE id = ?", [id]); } else { await dbPool.query("UPDATE tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", [id]); }
        const [updatedTickets] = await dbPool.query(`SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`, [id]);
        const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [id]);
        const updatedTicket = updatedTickets[0];
        updatedTicket.messages = messages;
        res.json(updatedTicket);
    } catch(error) { next(error) }
    });
app.post('/api/tickets/:id/close', verifyToken, verifyRole('seller', 'admin'), actionLimiter, async (req, res, next) => { try { const { id } = req.params; const [tickets] = await dbPool.query("SELECT * FROM tickets WHERE id = ?", [id]); if (tickets.length === 0) return res.status(404).json({ message: 'Ticket not found.' }); await dbPool.query("UPDATE tickets SET status = 'completed', updated_at = CURRENT_TIMESTAMP WHERE id = ?", [id]); const [updatedTickets] = await dbPool.query(`SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`, [id]); const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [id]); const updatedTicket = updatedTickets[0]; updatedTicket.messages = messages; res.json(updatedTicket); } catch(error) { next(error) } });
app.delete('/api/tickets/:id', verifyToken, verifyRole('seller', 'admin'), actionLimiter, async (req, res, next) => { try { const { id } = req.params; const [tickets] = await dbPool.query("SELECT * FROM tickets WHERE id = ?", [id]); if (tickets.length === 0) return res.status(404).json({ message: 'Ticket not found.' }); await dbPool.query("DELETE FROM tickets WHERE id = ?", [id]); res.json({ success: true, message: `Ticket #${id} has been permanently deleted.` }); } catch(error) { next(error) } });

// --- PROTECTED ADMIN/SELLER ENDPOINTS ---
app.get('/api/clients', verifyToken, verifyRole('seller', 'admin'), apiLimiter, (req, res) => { res.json({ count: clients.size, clients: Array.from(clients.values()) }); });
app.post('/broadcast', verifyToken, verifyRole('admin'), actionLimiter, async (req, res, next) => { try { const { command } = req.body; if (!command) return res.status(400).json({ error: 'Missing "command"' }); const commandObj = { type: "execute", payload: command }; let successCount = 0; clients.forEach((c, id) => { pendingCommands.get(id)?.push(commandObj); successCount++; }); const commandType = typeof command === "string" ? "lua_script" : "json_action"; await dbPool.query("INSERT INTO commands (command_type, content, executed_by) VALUES (?, ?, ?)", [commandType, JSON.stringify(command), req.user.username]); res.json({ message: `Command broadcasted to ${successCount}/${clients.size} clients.` }); } catch(error) { next(error) } });
app.post('/kick', verifyToken, verifyRole('admin'), actionLimiter, (req, res) => { const { clientId } = req.body; const client = clients.get(clientId); if (!client) return res.status(404).json({ error: "Client not found." }); pendingCommands.get(clientId)?.push({ type: "kick" }); setTimeout(() => { clients.delete(clientId); pendingCommands.delete(clientId); }, 5000); res.json({ message: `Client ${client.username} kicked.` }); });
app.get('/uploads/:filename', verifyToken, verifyRole('seller', 'admin'), async (req, res, next) => { try { const filename = path.basename(req.params.filename); if (filename.includes('..')) { return res.status(400).send('Invalid filename.'); } const filePath = path.join(uploadDir, filename); const [records] = await dbPool.query("SELECT id FROM key_redemptions WHERE screenshot_filename = ?", [filename]); if (records.length === 0) { return res.status(404).json({ message: "File not found or access denied." }); } res.sendFile(filePath); } catch (error) { next(error); } });
app.post('/api/seller/redeem', verifyToken, verifyRole('seller', 'admin'), actionLimiter, upload.single('screenshot'), body('discordUsername').isNumeric().isLength({ min: 17, max: 20 }),
    async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) { addStrike(req.ip); return res.status(400).json({ errors: errors.array() }); }
        if (!req.file) { return res.status(400).json({ error: 'Screenshot file is required.' }); }
        const filename = `${nanoid(16)}.png`;
        const filePath = path.join(uploadDir, filename);
        try {
            await fs.promises.writeFile(filePath, req.file.buffer);
            const { discordUsername: discordUserId } = req.body;
            const adminUsername = req.user.username;
            const url = `https://api.luarmor.net/v3/projects/${process.env.LUARMOR_PROJECT_ID}/users`;
            const headers = { "Authorization": process.env.LUARMOR_API_KEY, "Content-Type": "application/json" };
            const payload = { "discord_id": discordUserId, "note": `Redeemed by ${adminUsername} on ${new Date().toLocaleDateString()}` };
            const luarmorResponse = await axios.post(url, payload, { headers });
            const data = luarmorResponse.data;
            if (data.success && data.user_key) {
                const newKey = data.user_key;
                await dbPool.query("INSERT INTO key_redemptions (redeemed_by_admin, discord_user_id, generated_key, screenshot_filename) VALUES (?, ?, ?, ?)", [adminUsername, discordUserId, newKey, filename]);
                res.json({ success: true, message: `Key successfully generated and linked to ${discordUserId}.`, generatedKey: newKey });
            } else {
                await fs.promises.unlink(filePath);
                res.status(400).json({ success: false, error: `Luarmor API Error: ${data.message || 'Unknown error.'}` });
            }
        } catch (error) { 
            if (fs.existsSync(filePath)) { await fs.promises.unlink(filePath); }
            next(error);
        }
    });
app.get('/api/executions', verifyToken, verifyRole('seller', 'admin'), apiLimiter, async (req, res, next) => { try { const data = await getAggregatedData('connections', 'connected_at', 'id', req.query.period, 'COUNT'); res.json(data); } catch(e) { next(e) } });
app.get('/api/player-stats', verifyToken, verifyRole('seller', 'admin'), apiLimiter, async (req, res, next) => { try { const data = await getAggregatedData('player_snapshots', 'created_at', 'player_count', req.query.period, 'MAX'); res.json(data); } catch(e) { next(e) } });
app.get('/api/seller/keys-sold', verifyToken, verifyRole('seller', 'admin'), apiLimiter, async (req, res, next) => { try { const data = await getAggregatedData('key_redemptions', 'redeemed_at', 'id', req.query.period, 'COUNT'); res.json(data); } catch(e) { next(e) } });
app.get('/api/seller/sales-log', verifyToken, verifyRole('seller', 'admin'), apiLimiter, async (req, res, next) => { try { const [rows] = await dbPool.query("SELECT * FROM key_redemptions ORDER BY redeemed_at DESC"); res.json(rows); } catch(e) { next(e) } });

// --- GAME CLIENT ENDPOINTS ---
app.post('/connect', globalIpLimiter, async (req, res, next) => { 
    try {
        const { id, username, gameName, serverInfo, playerCount, userId } = req.body;
        if (!id || !username) return res.status(400).json({ error: "Missing required fields." });
        clients.set(id, { id, username, gameName, serverInfo, playerCount, userId, connectedAt: new Date(), lastSeen: Date.now() });
        if (!pendingCommands.has(id)) pendingCommands.set(id, []);
        console.log(`[CONNECT] Client registered: ${username} (ID: ${id})`);
        await dbPool.query("INSERT INTO connections (client_id, username, user_id, game_name, server_info, player_count, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)", [id, username, userId, gameName, serverInfo, playerCount, req.ip]);
        res.json({ message: "Successfully registered." });
    } catch(e) { next(e) }
});
app.post('/poll', globalIpLimiter, (req, res) => { const { id } = req.body; if (!id || !clients.has(id)) return res.status(404).json({ error: "Client not registered." }); clients.get(id).lastSeen = Date.now(); const commands = pendingCommands.get(id) || []; pendingCommands.set(id, []); res.json({ commands }); });

// --- UTILITY FUNCTIONS & INTERVALS ---
async function getAggregatedData(tableName, dateColumn, valueColumn, period, aggregationFn = 'COUNT') { let interval, groupByFormat; switch (period) { case 'daily': interval = '24 HOUR'; groupByFormat = '%Y-%m-%d %H:00:00'; break; case 'weekly': interval = '7 DAY'; groupByFormat = '%Y-%m-%d'; break; default: interval = '30 DAY'; groupByFormat = '%Y-%m-%d'; break; } const query = `SELECT DATE_FORMAT(${dateColumn}, ?) AS date, ${aggregationFn}(${valueColumn}) AS count FROM ${tableName} WHERE ${dateColumn} >= NOW() - INTERVAL ${interval} GROUP BY date ORDER BY date ASC;`; const [rows] = await dbPool.query(query, [groupByFormat]); return rows; }
setInterval(() => { const now = Date.now(); clients.forEach((client, id) => { if (now - client.lastSeen > CLIENT_TIMEOUT_MS) { clients.delete(id); pendingCommands.delete(id); console.log(`[TIMEOUT] Kicked inactive client: ${client.username} (ID: ${id})`); } }); }, 5000);
setInterval(async () => { if (clients.size > 0) { try { await dbPool.query("INSERT INTO player_snapshots (player_count) VALUES (?)", [clients.size]); } catch (error) { console.error("[DB] Failed to log player snapshot:", error.message); } } }, SNAPSHOT_INTERVAL_MS);
setInterval(() => { const now = Date.now(); for (const [ip, expiry] of ipBanList.entries()) { if (now > expiry) { ipBanList.delete(ip); console.log(`[SECURITY] Unbanned IP: ${ip}`); } } for (const [ip, record] of strikeTracker.entries()) { if (now - record.firstStrikeTimestamp > STRIKE_TIMEFRAME_MS) { strikeTracker.delete(ip); } } }, 5 * 60 * 1000);

// --- GLOBAL ERROR HANDLER ---
app.use((err, req, res, next) => {
    console.error(err);
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({ message: 'Invalid CSRF token. Request blocked.' });
    }
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ message: `File upload error: ${err.message}` });
    }
    res.status(500).json({ message: 'An unexpected server error occurred.' });
});

// --- START SERVER ---
async function startServer() {
    await initializeDatabase();
    app.listen(PORT, () => console.log(`Aperture Command Server running on port ${PORT}`));
}
startServer();
