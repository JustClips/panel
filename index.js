// Rolbox Command Server - FORTRESS EDITION
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const multer = require('multer');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
// <<< SECURITY UPGRADE >>> Import tools for validating and sanitizing user input
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_TIMEOUT_MS = 15000;
const SNAPSHOT_INTERVAL_MS = 5 * 60 * 1000;

// --- SECURITY & CORE MIDDLEWARE ---
// <<< SECURITY UPGRADE >>> Helmet with a stricter Content Security Policy to prevent XSS attacks.
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"], // Only allow resources from your own domain by default
            scriptSrc: ["'self'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"], // Allow scripts from your domain, and trusted CDNs
            styleSrc: ["'self'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "'unsafe-inline'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:"], // Allow images from your domain and data URIs
            connectSrc: ["'self'"] // Only allow API connections to your own domain
        }
    }
}));


const allowedOrigins = [
    'https://w1ckllon.com', // Your production domain
    process.env.RAILWAY_STATIC_URL, // Your Railway app's URL
    'http://localhost:5500',
    'http://127.0.0.1:5500'
].filter(Boolean); // Filter out any undefined environment variables

app.use(cors({
    origin: function(origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('This origin is not allowed by CORS'));
        }
    }
}));

app.use(bodyParser.json({ limit: '5mb' })); // <<< SECURITY UPGRADE >>> Reduced payload limit
app.use(bodyParser.urlencoded({ extended: true, limit: '5mb' }));

// SERVE THE FRONTEND PANEL
app.use(express.static('public'));

// --- FILE UPLOAD & STATIC SERVING ---
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) { fs.mkdirSync(uploadDir); }
app.use('/uploads', express.static('uploads'));
const storage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, uploadDir); },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB
    fileFilter: (req, file, cb) => {
        if (file.mimetype === "image/png") {
            cb(null, true);
        } else {
            cb(new Error("Only .png files are allowed!"), false);
        }
    }
});

let clients = new Map();
let pendingCommands = new Map();

// --- MYSQL DATABASE SETUP ---
const dbPool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// --- DATABASE INITIALIZATION ---
async function initializeDatabase() {
    try {
        const connection = await dbPool.getConnection();
        console.log("Successfully connected to MySQL database.");
        // <<< SECURITY UPGRADE >>> Added 'role' column for Role-Based Access Control (RBAC)
        await connection.query(`CREATE TABLE IF NOT EXISTS adminusers (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, role ENUM('buyer', 'seller', 'admin') NOT NULL DEFAULT 'buyer', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        
        // <<< SECURITY UPGRADE >>> Idempotent schema migration: add role column if it doesn't exist
        const [columns] = await connection.query("SHOW COLUMNS FROM `adminusers` LIKE 'role'");
        if (columns.length === 0) {
            console.log("Upgrading 'adminusers' table, adding 'role' column...");
            await connection.query("ALTER TABLE `adminusers` ADD COLUMN `role` ENUM('buyer', 'seller', 'admin') NOT NULL DEFAULT 'buyer' AFTER `password_hash`;");
        }
        
        await connection.query(`CREATE TABLE IF NOT EXISTS connections (id INT AUTO_INCREMENT PRIMARY KEY, client_id VARCHAR(255) NOT NULL, username VARCHAR(255) NOT NULL, user_id BIGINT, game_name VARCHAR(255), server_info VARCHAR(255), player_count INT, connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS commands (id INT AUTO_INCREMENT PRIMARY KEY, command_type VARCHAR(50) NOT NULL, content TEXT, executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS player_snapshots (id INT AUTO_INCREMENT PRIMARY KEY, player_count INT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS key_redemptions (id INT AUTO_INCREMENT PRIMARY KEY, redeemed_by_admin VARCHAR(255) NOT NULL, discord_user_id VARCHAR(255) NOT NULL, generated_key VARCHAR(255) NOT NULL, screenshot_filename VARCHAR(255), redeemed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS tickets (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, status ENUM('awaiting', 'processing', 'completed') DEFAULT 'awaiting', license_key VARCHAR(255), payment_method VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES adminusers(id));`);
        await connection.query(`CREATE TABLE IF NOT EXISTS ticket_messages (id INT AUTO_INCREMENT PRIMARY KEY, ticket_id INT NOT NULL, sender ENUM('user', 'seller') NOT NULL, message TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE);`);

        const allUsers = [ { username: 'Vandelz', password: 'Vandelzseller1', role: 'seller' }, { username: 'zuse35', password: 'zuse35seller1', role: 'seller' }, { username: 'Duzin', password: 'Duzinseller1', role: 'seller' }, { username: 'swiftkey', password: 'swiftkeyseller1', role: 'seller' }, { username: 'vupxy', password: 'vupxydev', role: 'admin' }, { username: 'megamind', password: 'megaminddev', role: 'admin' }];
        for (const user of allUsers) { const [existingUser] = await connection.query("SELECT * FROM adminusers WHERE username = ?", [user.username]); if (existingUser.length === 0) { console.log(`Creating user: ${user.username}...`); const hashedPassword = await bcrypt.hash(user.password, 10); await connection.query("INSERT INTO adminusers (username, password_hash, role) VALUES (?, ?, ?)", [user.username, hashedPassword, user.role]); console.log(`User ${user.username} created.`); } else if (existingUser[0].role !== user.role) { console.log(`Updating role for user: ${user.username}`); await connection.query("UPDATE adminusers SET role = ? WHERE username = ?", [user.role, user.username]); } }
        connection.release();
        console.log("Database initialization complete.");
    } catch (error) {
        console.error("!!! DATABASE INITIALIZATION FAILED !!!", error);
        process.exit(1);
    }
}


// --- AUTHENTICATION & AUTHORIZATION MIDDLEWARE ---
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

// <<< SECURITY UPGRADE >>> Middleware to check if a user has one of the allowed roles
const verifyRole = (...allowedRoles) => {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Forbidden: You do not have permission for this action.' });
        }
        next();
    };
};

// --- RATE LIMITERS ---
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: 'Too many authentication attempts. Please try again later.' });
const actionLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, keyGenerator: (req, res) => req.user.id, standardHeaders: true, legacyHeaders: false, message: { message: "Too many sensitive actions. Please try again in an hour." } });
const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, keyGenerator: (req, res) => req.user.id, standardHeaders: true, legacyHeaders: false, message: { message: "API rate limit exceeded." } });


// --- AUTHENTICATION ENDPOINTS ---
app.post('/register', authLimiter,
    body('username').isLength({ min: 3, max: 20 }).withMessage('Username must be 3-20 characters long.').isAlphanumeric().withMessage('Username must be alphanumeric.').trim().escape(),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long.'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
        const { username, password } = req.body;
        try {
            const [existingUsers] = await dbPool.query("SELECT id FROM adminusers WHERE username = ?", [username]);
            if (existingUsers.length > 0) return res.status(409).json({ message: 'Username already taken.' });
            const hashedPassword = await bcrypt.hash(password, 10);
            await dbPool.query("INSERT INTO adminusers (username, password_hash, role) VALUES (?, ?, 'buyer')", [username, hashedPassword]);
            res.status(201).json({ success: true, message: 'User created successfully.' });
        } catch (error) {
            console.error('Registration error:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    });

app.post('/login', authLimiter, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || !process.env.JWT_SECRET) return res.status(400).json({ message: 'Invalid request or server config error.' });
    try {
        const [rows] = await dbPool.query("SELECT * FROM adminusers WHERE username = ?", [username]);
        if (rows.length === 0) return res.status(401).json({ message: 'Invalid credentials' });
        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });
        const payload = { id: user.id, username: user.username, role: user.role };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '8h' });
        res.json({ success: true, token, username: user.username });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/verify-token', verifyToken, (req, res) => {
    res.json({ success: true, message: 'Token is valid.', user: { id: req.user.id, username: req.user.username, role: req.user.role } });
});


// --- TICKET ENDPOINTS ---
app.get('/tickets/my', verifyToken, apiLimiter, async (req, res) => {
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

app.get('/tickets/all', verifyToken, verifyRole('seller', 'admin'), apiLimiter, async (req, res) => {
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

app.post('/tickets', verifyToken, actionLimiter, 
    body('paymentMethod').isLength({ min: 2, max: 50 }).withMessage("Invalid payment method format.").trim().escape(),
    async (req, res) => { 
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
        const { paymentMethod } = req.body;
        try {
            const licenseKey = "PENDING-" + Date.now();
            const [result] = await dbPool.query("INSERT INTO tickets (user_id, license_key, payment_method, status) VALUES (?, ?, ?, 'awaiting')", [req.user.id, licenseKey, paymentMethod]);
            const ticketId = result.insertId;
            let message = `Welcome! A seller will be with you shortly to help you purchase with ${paymentMethod}.`;
            await dbPool.query("INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, ?, ?)", [ticketId, 'seller', message]);
            const [tickets] = await dbPool.query(`SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`, [ticketId]);
            const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [ticketId]);
            const ticket = tickets[0];
            ticket.messages = messages;
            res.status(201).json(ticket);
        } catch (error) {
            console.error('Error creating ticket:', error);
            res.status(500).json({ message: 'Failed to create ticket' });
        }
    });

app.post('/tickets/:id/messages', verifyToken, apiLimiter,
    body('message').isLength({ min: 1, max: 2000 }).withMessage("Message is too long.").trim().escape(),
    async (req, res) => { 
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
        const { id } = req.params;
        const { message } = req.body;
        try {
            const [tickets] = await dbPool.query("SELECT * FROM tickets WHERE id = ?", [id]);
            if (tickets.length === 0) { return res.status(404).json({ message: 'Ticket not found.' }); }
            const ticket = tickets[0];
            const senderType = (ticket.user_id === req.user.id) ? 'user' : 'seller';
            await dbPool.query("INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, ?, ?)", [id, senderType, message]);
            if (ticket.status === 'awaiting') {
                 await dbPool.query("UPDATE tickets SET status = 'processing', updated_at = CURRENT_TIMESTAMP WHERE id = ?", [id]);
            } else {
                 await dbPool.query("UPDATE tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", [id]);
            }
            const [updatedTickets] = await dbPool.query(`SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`, [id]);
            const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [id]);
            const updatedTicket = updatedTickets[0];
            updatedTicket.messages = messages;
            res.json(updatedTicket);
        } catch (error) {
            console.error('Error adding message:', error);
            res.status(500).json({ message: 'Failed to add message' });
        }
    });

app.post('/api/tickets/:id/close', verifyToken, verifyRole('seller', 'admin'), actionLimiter, async (req, res) => {
    const { id } = req.params;
    try {
        const [tickets] = await dbPool.query("SELECT * FROM tickets WHERE id = ?", [id]);
        if (tickets.length === 0) { return res.status(404).json({ message: 'Ticket not found.' }); }
        await dbPool.query("UPDATE tickets SET status = 'completed', updated_at = CURRENT_TIMESTAMP WHERE id = ?", [id]);
        const [updatedTickets] = await dbPool.query(`SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`, [id]);
        const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [id]);
        const updatedTicket = updatedTickets[0];
        updatedTicket.messages = messages;
        res.json(updatedTicket);
    } catch (error) {
        console.error('Error closing ticket:', error);
        res.status(500).json({ message: 'Failed to close ticket' });
    }
});

app.delete('/api/tickets/:id', verifyToken, verifyRole('seller', 'admin'), actionLimiter, async (req, res) => {
    const { id } = req.params;
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
});


// --- PROTECTED ADMIN/SELLER ENDPOINTS ---
app.get('/api/clients', verifyToken, verifyRole('seller', 'admin'), apiLimiter, (req, res) => {
    res.json({ count: clients.size, clients: Array.from(clients.values()) });
});

app.post('/broadcast', verifyToken, verifyRole('admin'), actionLimiter, async (req, res) => {
    const { command } = req.body;
    if (!command) return res.status(400).json({ error: 'Missing "command"' });
    const commandObj = { type: "execute", payload: command };
    let successCount = 0;
    clients.forEach((c, id) => {
        pendingCommands.get(id)?.push(commandObj);
        successCount++;
    });
    try {
        const commandType = typeof command === "string" ? "lua_script" : "json_action";
        await dbPool.query("INSERT INTO commands (command_type, content) VALUES (?, ?)", [commandType, JSON.stringify(command)]);
    } catch (error) { 
        console.error("[DB] Failed to log broadcast command:", error.message); 
    }
    res.json({ message: `Command broadcasted to ${successCount}/${clients.size} clients.` });
});

app.post('/kick', verifyToken, verifyRole('admin'), actionLimiter, (req, res) => {
    const { clientId } = req.body;
    const client = clients.get(clientId);
    if (!client) return res.status(404).json({ error: "Client not found." });
    
    pendingCommands.get(clientId)?.push({ type: "kick" });
    setTimeout(() => {
        clients.delete(clientId);
        pendingCommands.delete(clientId);
    }, 5000);
    
    res.json({ message: `Client ${client.username} kicked.` });
});

app.post('/api/seller/redeem', verifyToken, verifyRole('seller', 'admin'), actionLimiter, upload.single('screenshot'),
    body('discordUsername').isNumeric().withMessage('Discord ID must be numeric.').isLength({ min: 17, max: 20 }).withMessage('Invalid Discord ID length.'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            if (req.file) fs.unlinkSync(req.file.path);
            return res.status(400).json({ errors: errors.array() });
        }
        const { discordUsername: discordUserId } = req.body;
        const adminUsername = req.user.username;
        if (!req.file) return res.status(400).json({ error: 'Screenshot file is required.' });
        if (!process.env.LUARMOR_API_KEY || !process.env.LUARMOR_PROJECT_ID) {
            return res.status(500).json({ error: "Luarmor API is not configured on the server." });
        }
        const url = `https://api.luarmor.net/v3/projects/${process.env.LUARMOR_PROJECT_ID}/users`;
        const headers = { "Authorization": process.env.LUARMOR_API_KEY, "Content-Type": "application/json" };
        const payload = { "discord_id": discordUserId, "note": `Redeemed by ${adminUsername} on ${new Date().toLocaleDateString()}` };
        try {
            const luarmorResponse = await axios.post(url, payload, { headers });
            const data = luarmorResponse.data;
            if (data.success && data.user_key) {
                const newKey = data.user_key;
                await dbPool.query(
                    "INSERT INTO key_redemptions (redeemed_by_admin, discord_user_id, generated_key, screenshot_filename) VALUES (?, ?, ?, ?)",
                    [adminUsername, discordUserId, newKey, req.file.filename]
                );
                res.json({ success: true, message: `Key successfully generated and linked to ${discordUserId}.`, generatedKey: newKey });
            } else {
                if (req.file) fs.unlinkSync(req.file.path);
                res.status(400).json({ success: false, error: `Luarmor API Error: ${data.message || 'Unknown error.'}` });
            }
        } catch (error) {
            if (req.file) fs.unlinkSync(req.file.path);
            console.error("Luarmor API request failed:", error.response ? error.response.data : error.message);
            res.status(500).json({ error: 'An internal error occurred while communicating with the key service.' });
        }
    });

app.get('/api/executions', verifyToken, verifyRole('seller', 'admin'), apiLimiter, async (req, res) => {
    try {
        const data = await getAggregatedData('connections', 'connected_at', 'id', req.query.period, 'COUNT');
        res.json(data);
    } catch (error) { res.status(500).json({ error: "Failed to retrieve connection statistics." }); }
});

app.get('/api/player-stats', verifyToken, verifyRole('seller', 'admin'), apiLimiter, async (req, res) => {
    try {
        const data = await getAggregatedData('player_snapshots', 'created_at', 'player_count', req.query.period, 'MAX');
        res.json(data);
    } catch (error) { res.status(500).json({ error: 'Failed to retrieve player statistics.' }); }
});

app.get('/api/seller/keys-sold', verifyToken, verifyRole('seller', 'admin'), apiLimiter, async (req, res) => {
    try {
        const data = await getAggregatedData('key_redemptions', 'redeemed_at', 'id', req.query.period, 'COUNT');
        res.json(data);
    } catch (error) { res.status(500).json({ error: 'Failed to retrieve key redemption statistics.' }); }
});

app.get('/api/seller/sales-log', verifyToken, verifyRole('seller', 'admin'), apiLimiter, async (req, res) => {
    try {
        const [rows] = await dbPool.query("SELECT * FROM key_redemptions ORDER BY redeemed_at DESC");
        res.json(rows);
    } catch (error) { console.error("Failed to retrieve sales log:", error); res.status(500).json({ error: 'Failed to retrieve sales log.' }); }
});


// --- GAME CLIENT ENDPOINTS ---
app.post('/connect', async (req, res) => {
    const { id, username, gameName, serverInfo, playerCount, userId } = req.body;
    if (!id || !username) return res.status(400).json({ error: "Missing required fields." });
    clients.set(id, { id, username, gameName, serverInfo, playerCount, userId, connectedAt: new Date(), lastSeen: Date.now() });
    if (!pendingCommands.has(id)) pendingCommands.set(id, []);
    console.log(`[CONNECT] Client registered: ${username} (ID: ${id})`);
    try {
        await dbPool.query(
            "INSERT INTO connections (client_id, username, user_id, game_name, server_info, player_count) VALUES (?, ?, ?, ?, ?, ?)", 
            [id, username, userId, gameName, serverInfo, playerCount]
        );
    } catch (error) { console.error(`[DB] Failed to log connection for ${username}:`, error.message); }
    res.json({ message: "Successfully registered." });
});

app.post('/poll', (req, res) => {
    const { id } = req.body;
    if (!id || !clients.has(id)) return res.status(404).json({ error: "Client not registered." });
    clients.get(id).lastSeen = Date.now();
    const commands = pendingCommands.get(id) || [];
    pendingCommands.set(id, []);
    res.json({ commands });
});


// --- UTILITY FUNCTIONS & INTERVALS ---
async function getAggregatedData(tableName, dateColumn, valueColumn, period, aggregationFn = 'COUNT') {
    let interval, groupByFormat;
    switch (period) {
        case 'daily': interval = '24 HOUR'; groupByFormat = '%Y-%m-%d %H:00:00'; break;
        case 'weekly': interval = '7 DAY'; groupByFormat = '%Y-%m-%d'; break;
        default: interval = '30 DAY'; groupByFormat = '%Y-%m-%d'; break;
    }
    const query = `SELECT DATE_FORMAT(${dateColumn}, ?) AS date, ${aggregationFn}(${valueColumn}) AS count FROM ${tableName} WHERE ${dateColumn} >= NOW() - INTERVAL ${interval} GROUP BY date ORDER BY date ASC;`;
    const [rows] = await dbPool.query(query, [groupByFormat]);
    return rows;
}

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
        } catch (error) { console.error("[DB] Failed to log player snapshot:", error.message); }
    }
}, SNAPSHOT_INTERVAL_MS);


// <<< SECURITY UPGRADE >>> Global error handler to catch all unhandled errors and prevent leaking stack traces.
app.use((err, req, res, next) => {
    console.error(err.stack); // Log the full error for your own debugging
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ message: `File upload error: ${err.message}` });
    }
    res.status(500).json({ message: 'An unexpected internal server error occurred.' });
});

// --- START SERVER ---
async function startServer() {
    await initializeDatabase();
    app.listen(PORT, () => console.log(`Aperture Command Server running on port ${PORT}`));
}

startServer();
