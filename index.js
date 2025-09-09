// Rolbox Command Server - Upgraded with MySQL, File Uploads & Luarmor Integration
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
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_TIMEOUT_MS = 30000; // Increased timeout to 30 seconds
const SNAPSHOT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

// --- SERVE FRONTEND STATIC FILES ---
// This tells Express to serve any files in the 'public' folder.
app.use(express.static(path.join(__dirname, 'public')));

// --- TRUST PROXY FOR RAILWAY ---
// This is important for correctly identifying the client's IP address when behind a proxy like Railway's.
app.set('trust proxy', 1);

// --- SECURITY & CORE MIDDLEWARE ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"], // 'unsafe-inline' for inline script in HTML
            "style-src": ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
            "font-src": ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"],
            "img-src": ["'self'", "data:", "https://i.imgur.com"]
        }
    }
}));

// Define allowed origins for CORS. Add your frontend domains here.
const allowedOrigins = [
  'https://eps1llon.win',
  'https://www.eps1llon.win'
];

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.error(`CORS Blocked Origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Pre-flight request handling

app.use(bodyParser.json({ limit: '100kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '100kb' }));

// --- ADDITIONAL SECURITY MIDDLEWARE ---
const validateRequest = (req, res, next) => {
    const userAgent = req.headers['user-agent'] || '';
    const suspiciousAgents = ['bot', 'crawler', 'scanner', 'curl', 'wget'];
    if (suspiciousAgents.some(agent => userAgent.toLowerCase().includes(agent))) {
        console.warn(`Suspicious user agent detected: ${userAgent} from ${req.ip}`);
    }
    const contentLength = parseInt(req.headers['content-length']);
    if (contentLength > 10 * 1024 * 1024) { // 10MB limit
        return res.status(413).json({ error: 'Payload too large' });
    }
    next();
};

app.use(validateRequest);

// --- FILE UPLOAD & STATIC SERVING ---
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}
// Serve uploaded files statically
app.use('/uploads', express.static(uploadDir));

// Multer configuration for file storage
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

// Multer middleware for handling PNG file uploads
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB file size limit
        files: 1
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype !== "image/png" || !file.originalname.match(/\.(png)$/i)) {
            return cb(new Error("Only .png files are allowed!"), false);
        }
        cb(null, true);
    }
});

// In-memory stores for connected game clients
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
        console.log("Successfully connected to MySQL database.");

        await connection.query(`CREATE TABLE IF NOT EXISTS connections (id INT AUTO_INCREMENT PRIMARY KEY, client_id VARCHAR(255) NOT NULL, username VARCHAR(255) NOT NULL, user_id BIGINT, game_name VARCHAR(255), server_info VARCHAR(255), player_count INT, connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS commands (id INT AUTO_INCREMENT PRIMARY KEY, command_type VARCHAR(50) NOT NULL, content TEXT, executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS player_snapshots (id INT AUTO_INCREMENT PRIMARY KEY, player_count INT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS adminusers (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, role ENUM('admin','seller','buyer') NOT NULL DEFAULT 'buyer', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS key_redemptions (id INT AUTO_INCREMENT PRIMARY KEY, redeemed_by_admin VARCHAR(255) NOT NULL, discord_user_id VARCHAR(255) NOT NULL, generated_key VARCHAR(255) NOT NULL, screenshot_filename VARCHAR(255), redeemed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS tickets (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, status ENUM('awaiting', 'processing', 'completed') DEFAULT 'awaiting', license_key VARCHAR(255), payment_method VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES adminusers(id));`);
        await connection.query(`CREATE TABLE IF NOT EXISTS ticket_messages (id INT AUTO_INCREMENT PRIMARY KEY, ticket_id INT NOT NULL, sender ENUM('user', 'seller') NOT NULL, message TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS user_locations (id INT AUTO_INCREMENT PRIMARY KEY, client_id VARCHAR(255) NOT NULL, username VARCHAR(255) NOT NULL, city VARCHAR(255), country VARCHAR(255), latitude DECIMAL(10, 8), longitude DECIMAL(11, 8), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, INDEX idx_client_id (client_id), INDEX idx_country (country));`);
        await connection.query(`CREATE TABLE IF NOT EXISTS executor_stats (id INT AUTO_INCREMENT PRIMARY KEY, client_id VARCHAR(255) NOT NULL, username VARCHAR(255) NOT NULL, executor_name VARCHAR(255), executor_version VARCHAR(255), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, INDEX idx_executor (executor_name));`);

        connection.release();
        console.log("Database initialization complete.");
    } catch (error) {
        console.error("!!! DATABASE INITIALIZATION FAILED !!!", error);
        process.exit(1);
    }
}

// --- AUTHENTICATION MIDDLEWARE ---
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

// --- ROLE-BASED AUTHORIZATION MIDDLEWARE ---
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

// --- INPUT VALIDATION MIDDLEWARE ---
const validateTicketCreation = [body('paymentMethod').trim().notEmpty().isIn(['PayPal', 'Crypto', 'Credit Card', 'Bank Transfer', 'Google Pay', 'Apple Pay', 'CashApp', 'Gag Pets', 'Secret Brainrots']).withMessage('Invalid payment method selected.').isLength({ min: 2, max: 50 }).withMessage('Payment method must be between 2 and 50 characters.')];
const validateTicketMessage = [body('message').trim().notEmpty().withMessage('Message cannot be empty.').isLength({ min: 1, max: 1000 }).withMessage('Message must be between 1 and 1000 characters.').escape()];
const validateKeyRedemption = [body('discordUsername').trim().isLength({ min: 17, max: 20 }).isNumeric().withMessage('Invalid Discord ID format')];

// =================================================================
// --- API ROUTES ---
// We use a router and prefix all API calls with /api to keep them separate from frontend pages
// =================================================================
const apiRouter = express.Router();


// --- AUTHENTICATION ENDPOINTS ---
apiRouter.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || username.length < 3 || password.length > 30 || password.length < 6 || password.length > 100) {
        return res.status(400).json({ message: 'Invalid username or password length.' });
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

apiRouter.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ message: 'Invalid request.' });
    }
    try {
        const [rows] = await dbPool.query("SELECT * FROM adminusers WHERE username = ?", [username]);
        if (rows.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

        const payload = { id: user.id, username: user.username, role: user.role };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '8h' });

        res.json({ success: true, token, username: user.username, role: user.role });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

apiRouter.get('/verify-token', verifyToken, (req, res) => {
    res.json({ user: req.user });
});

apiRouter.post('/logout', (req, res) => {
    res.json({ success: true });
});

// --- TICKET ENDPOINTS ---
apiRouter.get('/tickets/my', verifyToken, requireAnyRole, async (req, res) => {
    try {
        const [tickets] = await dbPool.query(`SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.user_id = ? ORDER BY t.updated_at DESC`, [req.user.id]);
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

apiRouter.get('/tickets/all', verifyToken, requireSeller, async (req, res) => {
    try {
        const [tickets] = await dbPool.query(`SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id ORDER BY t.updated_at DESC`);
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

apiRouter.post('/tickets', verifyToken, requireBuyer, validateTicketCreation, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ message: 'Validation failed', errors: errors.array().map(e => e.msg) });
    }
    const { paymentMethod } = req.body;
    try {
        const [existingTickets] = await dbPool.query("SELECT id FROM tickets WHERE user_id = ? AND status != 'completed'", [req.user.id]);
        if (existingTickets.length > 0) {
            return res.status(400).json({ message: 'You already have an open ticket. Please wait for it to be processed.' });
        }
        const [result] = await dbPool.query("INSERT INTO tickets (user_id, license_key, payment_method, status) VALUES (?, ?, ?, 'awaiting')", [req.user.id, "PENDING-" + Date.now(), paymentMethod]);
        const ticketId = result.insertId;
        await dbPool.query("INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, ?, ?)", [ticketId, 'seller', `Welcome! A seller will be with you shortly to help you purchase with ${paymentMethod}.`]);

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

apiRouter.post('/tickets/:id/messages', verifyToken, requireAnyRole, validateTicketMessage, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: 'Validation failed', errors: errors.array().map(e => e.msg) });

    const { id } = req.params;
    const { message } = req.body;
    try {
        const [tickets] = await dbPool.query("SELECT * FROM tickets WHERE id = ?", [id]);
        if (tickets.length === 0) return res.status(404).json({ message: 'Ticket not found.' });
        const ticket = tickets[0];
        if (req.user.role === 'buyer' && ticket.user_id !== req.user.id) {
            return res.status(403).json({ message: 'You can only send messages to your own tickets.' });
        }
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

apiRouter.post('/tickets/:id/close', verifyToken, requireSeller, async (req, res) => {
    const { id } = req.params;
    try {
        const [tickets] = await dbPool.query("SELECT * FROM tickets WHERE id = ?", [id]);
        if (tickets.length === 0) return res.status(404).json({ message: 'Ticket not found.' });

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

apiRouter.delete('/tickets/:id', verifyToken, requireSeller, async (req, res) => {
    const { id } = req.params;
    try {
        const [tickets] = await dbPool.query("SELECT * FROM tickets WHERE id = ?", [id]);
        if (tickets.length === 0) return res.status(404).json({ message: 'Ticket not found.' });

        await dbPool.query("DELETE FROM tickets WHERE id = ?", [id]);
        res.json({ success: true, message: `Ticket #${id} has been permanently deleted.` });
    } catch (error) {
        console.error('Error deleting ticket:', error);
        res.status(500).json({ message: 'Failed to delete ticket' });
    }
});

// --- GAME CLIENT ENDPOINTS ---
// These are not prefixed because they are hit by an external client, not the frontend website
app.post('/connect', async (req, res) => {
    const { id, username, gameName, serverInfo, playerCount, userId, city, country, executorName, executorVersion } = req.body;
    if (!id || !username) return res.status(400).json({ error: "Missing required fields." });
    
    clients.set(id, { id, username, gameName, serverInfo, playerCount, userId, city, country, executorName, executorVersion, connectedAt: new Date(), lastSeen: Date.now() });
    if (!pendingCommands.has(id)) pendingCommands.set(id, []);

    try {
        await dbPool.query("INSERT INTO connections (client_id, username, user_id, game_name, server_info, player_count) VALUES (?, ?, ?, ?, ?, ?)", [id, username, userId, gameName, serverInfo, playerCount]);
    } catch (error) {
        console.error(`[DB] Failed to log connection for ${username}:`, error.message);
    }
    res.json({ message: "Successfully registered." });
});

app.post('/heartbeat', async (req, res) => {
    const { id } = req.body;
    if (!id || !clients.has(id)) return res.status(404).json({ error: "Client not registered." });
    clients.get(id).lastSeen = Date.now();
    res.json({ message: "Heartbeat received." });
});

app.post('/poll', (req, res) => {
    const { id } = req.body;
    if (!id || !clients.has(id)) return res.status(404).json({ error: "Client not registered." });
    clients.get(id).lastSeen = Date.now();
    const commands = pendingCommands.get(id) || [];
    pendingCommands.set(id, []);
    res.json({ commands });
});

// --- PROTECTED ADMIN/SELLER ENDPOINTS (on API router) ---
apiRouter.get('/clients', verifyToken, requireAnyRole, (req, res) => {
    res.json({ count: clients.size, clients: Array.from(clients.values()) });
});

apiRouter.post('/broadcast', verifyToken, requireAdmin, async (req, res) => {
    const { command } = req.body;
    if (!command) return res.status(400).json({ error: 'Missing "command"' });

    const commandObj = { type: "execute", payload: command };
    let successCount = 0;
    clients.forEach((c, id) => {
        pendingCommands.get(id)?.push(commandObj);
        successCount++;
    });
    res.json({ message: `Command broadcasted to ${successCount}/${clients.size} clients.` });
});

apiRouter.post('/command/targeted', verifyToken, requireAdmin, (req, res) => {
    const { clientIds, command } = req.body;
    if (!Array.isArray(clientIds) || !command) return res.status(400).json({ error: 'Missing "clientIds" array or "command".' });
    
    const commandObj = { type: "execute", payload: command };
    let successCount = 0;
    clientIds.forEach(id => {
        if (clients.has(id) && pendingCommands.has(id)) {
            pendingCommands.get(id).push(commandObj);
            successCount++;
        }
    });
    res.json({ message: `Command sent to ${successCount}/${clientIds.length} selected clients.` });
});

apiRouter.post('/seller/redeem', verifyToken, requireSeller, upload.single('screenshot'), validateKeyRedemption, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Validation failed', errors: errors.array().map(e => e.msg) });

    const { discordUsername: discordUserId } = req.body;
    const adminUsername = req.user.username;
    if (!req.file || !process.env.LUARMOR_API_KEY || !process.env.LUARMOR_PROJECT_ID) {
        return res.status(500).json({ error: "Server or request is misconfigured." });
    }
    const url = `https://api.luarmor.net/v3/projects/${process.env.LUARMOR_PROJECT_ID}/users`;
    const headers = { "Authorization": process.env.LUARMOR_API_KEY, "Content-Type": "application/json" };
    const payload = { "discord_id": discordUserId, "note": `Redeemed by ${adminUsername} on ${new Date().toLocaleDateString()}` };
    try {
        const luarmorResponse = await axios.post(url, payload, { headers, timeout: 10000 });
        const data = luarmorResponse.data;
        if (data.success && data.user_key) {
            await dbPool.query("INSERT INTO key_redemptions (redeemed_by_admin, discord_user_id, generated_key, screenshot_filename) VALUES (?, ?, ?, ?)", [adminUsername, discordUserId, data.user_key, req.file.filename]);
            res.json({ success: true, message: `Key successfully generated.`, generatedKey: data.user_key });
        } else {
            if (req.file.path) fs.unlinkSync(req.file.path);
            res.status(400).json({ success: false, error: `Luarmor Error: ${data.message || 'Unknown error.'}` });
        }
    } catch (error) {
        if (req.file.path) fs.unlinkSync(req.file.path);
        console.error("Luarmor API request failed:", error.response ? error.response.data : error.message);
        res.status(500).json({ error: 'An internal error occurred while communicating with the key service.' });
    }
});

// --- ANALYTICS & LOGS ENDPOINTS ---
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
apiRouter.get('/executions', verifyToken, requireAnyRole, async (req, res) => {
    try { res.json(await getAggregatedData('connections', 'connected_at', 'id', req.query.period, 'COUNT')); } 
    catch (e) { res.status(500).json({ error: "Failed to retrieve connection statistics." }); }
});
apiRouter.get('/player-stats', verifyToken, requireAnyRole, async (req, res) => {
    try { res.json(await getAggregatedData('player_snapshots', 'created_at', 'player_count', req.query.period, 'MAX')); } 
    catch (e) { res.status(500).json({ error: 'Failed to retrieve player statistics.' }); }
});
apiRouter.get('/seller/keys-sold', verifyToken, requireSeller, async (req, res) => {
    try { res.json(await getAggregatedData('key_redemptions', 'redeemed_at', 'id', req.query.period, 'COUNT')); }
    catch (e) { res.status(500).json({ error: 'Failed to retrieve key redemption statistics.' }); }
});
apiRouter.get('/seller/sales-log', verifyToken, requireSeller, async (req, res) => {
    try { const [rows] = await dbPool.query("SELECT * FROM key_redemptions ORDER BY redeemed_at DESC LIMIT 1000"); res.json(rows); }
    catch (e) { res.status(500).json({ error: 'Failed to retrieve sales log.' }); }
});
apiRouter.get('/locations', verifyToken, requireAnyRole, async (req, res) => {
    try { const [locations] = await dbPool.query(`SELECT DISTINCT city, country, latitude, longitude, COUNT(*) as user_count FROM user_locations WHERE latitude IS NOT NULL AND longitude IS NOT NULL GROUP BY city, country, latitude, longitude ORDER BY user_count DESC LIMIT 1000`); res.json(locations); }
    catch (e) { res.status(500).json({ error: 'Failed to fetch location data' }); }
});

// --- HEALTH CHECK ENDPOINT ---
apiRouter.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

// Use the apiRouter for all API calls
app.use('/api', apiRouter);

// --- FRONTEND ROUTE HANDLER ---
// This is the SPA catch-all. It sends the main HTML file for any request that doesn't match an API route or a static file.
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
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
            console.error("[DB] Failed to log player snapshot:", error.message);
        }
    }
}, SNAPSHOT_INTERVAL_MS);

// --- GLOBAL ERROR HANDLING MIDDLEWARE ---
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ error: `Upload error: ${err.message}` });
    }
    if (err.name === 'ValidationError') {
        return res.status(400).json({ error: err.message });
    }
    if (err.name === 'JsonWebTokenError') {
        return res.status(401).json({ error: 'Invalid token' });
    }
    res.status(500).json({ error: 'Internal server error' });
});

// --- START SERVER ---
async function startServer() {
    await initializeDatabase();
    app.listen(PORT, () => console.log(`Eps1llon Hub Server running on port ${PORT}`));
}

startServer();
