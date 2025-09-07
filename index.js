// Rolbox Command Server - Upgraded with MySQL Persistence & Proper Analytics
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser'); // NEW: For handling cookies
const rateLimit = require('express-rate-limit'); // NEW: For brute-force protection
const helmet = require('helmet'); // NEW: For security headers
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_TIMEOUT_MS = 15000;
const SNAPSHOT_INTERVAL_MS = 5 * 60 * 1000;

// --- SECURITY MIDDLEWARE ---

// NEW: Set security-related HTTP headers
app.use(helmet());

// NEW: Configure CORS to be more restrictive
// This allows your frontend to connect, but blocks other random websites.
const allowedOrigins = [
    'https://your-frontend-url.up.railway.app', // IMPORTANT: Replace with your actual admin panel URL
    'http://localhost:5500', // Example for local testing with Live Server
    'http://127.0.0.1:5500'  // Example for local testing
];

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true // NEW: Allow cookies to be sent from the frontend
}));


// --- STANDARD MIDDLEWARE ---
app.use(bodyParser.json({ limit: '5mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '5mb' }));
app.use(cookieParser()); // NEW: Use cookie parser middleware

// In-memory stores
let clients = new Map();
let pendingCommands = new Map();

function generateSessionId() {
    return require('crypto').randomBytes(32).toString('hex'); // More secure random ID
}

// --- MYSQL DATABASE SETUP ---
const dbConfig = process.env.DATABASE_URL ?
    { uri: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } } :
    {
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_DATABASE,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
    };
const dbPool = mysql.createPool(dbConfig);

// --- DATABASE INITIALIZATION ---
async function initializeDatabase() {
    try {
        const connection = await dbPool.getConnection();
        console.log("Successfully connected to MySQL database.");
        // (Database table creation logic remains the same...)
        await connection.query(`CREATE TABLE IF NOT EXISTS connections (id INT AUTO_INCREMENT PRIMARY KEY, client_id VARCHAR(255) NOT NULL, username VARCHAR(255) NOT NULL, user_id BIGINT, game_name VARCHAR(255), server_info VARCHAR(255), player_count INT, connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS commands (id INT AUTO_INCREMENT PRIMARY KEY, command_type VARCHAR(50) NOT NULL, content TEXT, executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS player_snapshots (id INT AUTO_INCREMENT PRIMARY KEY, player_count INT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS adminusers (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS sessions (session_id VARCHAR(255) PRIMARY KEY, user_id INT NOT NULL, username VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, expires_at TIMESTAMP NOT NULL, FOREIGN KEY (user_id) REFERENCES adminusers(id) ON DELETE CASCADE);`);
        const [cols] = await connection.query("SHOW COLUMNS FROM `connections`");
        const colNames = cols.map(c => c.Field);
        if (!colNames.includes("player_count")) { await connection.query("ALTER TABLE `connections` ADD COLUMN `player_count` INT DEFAULT 0;"); }
        if (!colNames.includes("game_name")) { await connection.query("ALTER TABLE `connections` ADD COLUMN `game_name` VARCHAR(255);"); }
        if (!colNames.includes("server_info")) { await connection.query("ALTER TABLE `connections` ADD COLUMN `server_info` VARCHAR(255);"); }
        if (!colNames.includes("user_id")) { await connection.query("ALTER TABLE `connections` ADD COLUMN `user_id` BIGINT;"); }
        const [adminUsers] = await connection.query("SELECT COUNT(*) as count FROM adminusers");
        if (adminUsers[0].count === 0) {
            console.log("Creating default admin users...");
            const hashedVupxy = await bcrypt.hash('vupxydev', 10);
            const hashedMegamind = await bcrypt.hash('megaminddev', 10);
            await connection.query("INSERT INTO adminusers (username, password_hash) VALUES (?, ?), (?, ?)", ['vupxy', hashedVupxy, 'megamind', hashedMegamind]);
            console.log("Default admin users created: vupxy, megamind");
        }
        connection.release();
        console.log("Database initialization complete.");
    } catch (error) {
        console.error("!!! DATABASE INITIALIZATION FAILED !!!", error);
        process.exit(1);
    }
}

// --- AUTHENTICATION MIDDLEWARE (CHANGED) ---
const authenticateSession = async (req, res, next) => {
    // CHANGED: Read session ID from the secure cookie instead of a header
    const sessionId = req.cookies.sessionId;
    if (!sessionId) {
        return res.status(401).json({ success: false, message: 'Unauthorized: No session token' });
    }
    try {
        const connection = await dbPool.getConnection();
        const [rows] = await connection.query(
            "SELECT s.*, u.username FROM sessions s JOIN adminusers u ON s.user_id = u.id WHERE s.session_id = ? AND s.expires_at > NOW()", [sessionId]
        );
        connection.release();
        if (rows.length === 0) {
            // Clear the invalid cookie from the user's browser
            res.clearCookie('sessionId');
            return res.status(401).json({ success: false, message: 'Unauthorized: Invalid or expired session' });
        }
        req.user = { id: rows[0].user_id, name: rows[0].username };
        next();
    } catch (error) {
        console.error('Session validation error:', error);
        return res.status(500).json({ success: false, message: 'Internal server error' });
    }
};

// --- API ENDPOINTS ---

// NEW: Rate limiter for the login route to prevent brute-force attacks
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 login requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, message: 'Too many login attempts. Please try again in 15 minutes.' }
});

app.get('/', (req, res) => {
    res.json({ message: 'Aperture Command Server is running!', clientsConnected: clients.size });
});

// CHANGED: Login endpoint now uses rate limiting and sets a secure cookie
app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required.' });
    }
    try {
        const connection = await dbPool.getConnection();
        const [rows] = await connection.query("SELECT * FROM adminusers WHERE username = ?", [username]);
        if (rows.length === 0) {
            connection.release();
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (isMatch) {
            const sessionId = generateSessionId();
            const expiresAt = new Date(Date.now() + (8 * 60 * 60 * 1000)); // 8 hours
            await connection.query(
                "INSERT INTO sessions (session_id, user_id, username, expires_at) VALUES (?, ?, ?, ?)", [sessionId, user.id, user.username, expiresAt]
            );
            connection.release();

            // CHANGED: Set a secure, HttpOnly cookie instead of sending the ID in the response body
            res.cookie('sessionId', sessionId, {
                httpOnly: true, // Prevents JavaScript from accessing the cookie
                secure: process.env.NODE_ENV === 'production', // Only send over HTTPS
                sameSite: 'strict', // Mitigates CSRF attacks
                expires: expiresAt
            });

            console.log('Login successful for admin:', username);
            // We no longer send the sessionId in the response body
            res.json({ success: true, username: user.username });
        } else {
            connection.release();
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// CHANGED: Logout now clears the cookie
app.post('/logout', (req, res) => {
    const sessionId = req.cookies.sessionId;
    if (sessionId) {
        dbPool.query("DELETE FROM sessions WHERE session_id = ?", [sessionId]).catch(err => {
            console.error("Error clearing session from DB on logout:", err);
        });
    }
    // Clear the cookie from the user's browser regardless
    res.clearCookie('sessionId');
    res.json({ success: true, message: 'Logged out successfully' });
});

// (The rest of your endpoints: /connect, /poll, /api/*, etc. remain unchanged but are now more secure because authenticateSession is stronger)

// --- GAME CLIENT ENDPOINTS (Unchanged) ---
app.post('/connect', async (req, res) => {
    const { id, username, gameName, serverInfo, playerCount, avatarUrl, userId } = req.body;
    if (!id || !username || !gameName || !serverInfo) { return res.status(400).json({ error: "Bad Request: Missing required fields." }) }
    if (clients.has(id)) { clients.get(id).lastSeen = Date.now(); return res.status(200).json({ type: "reconnected", clientId: id, message: "Heartbeat updated." }) }
    const clientData = { id, username, userId: userId || null, gameName, serverInfo, playerCount: typeof playerCount === "number" ? playerCount : null, avatarUrl: avatarUrl || null, connectedAt: new Date(), lastSeen: Date.now() };
    clients.set(id, clientData);
    if (!pendingCommands.has(id)) pendingCommands.set(id, []);
    console.log(`[CONNECT] Client registered: ${username} (ID: ${id})`);
    try {
        await dbPool.query("INSERT INTO connections (client_id, username, user_id, game_name, server_info, player_count) VALUES (?, ?, ?, ?, ?, ?)", [id, username, clientData.userId, gameName, serverInfo, clientData.playerCount]);
    } catch (error) {
        console.error(`[DB] Failed to log connection for ${username}:`, error.message)
    }
    res.json({ type: "connected", clientId: id, message: "Successfully registered." })
});

app.post('/poll', (req, res) => {
    const { id } = req.body; if (!id || !clients.has(id)) { return res.status(404).json({ error: `Client ${id} not registered.` }) }
    clients.get(id).lastSeen = Date.now(); const commands = pendingCommands.get(id) || [];
    pendingCommands.set(id, []); res.json({ commands })
});

// --- PROTECTED ADMIN ENDPOINTS ---
app.get('/api/clients', authenticateSession, (req, res) => {
    res.json({ count: clients.size, clients: Array.from(clients.values()) });
});

app.post('/broadcast', authenticateSession, async (req, res) => {
    const { command } = req.body; if (!command) return res.status(400).json({ error: 'Missing "command"' });
    const commandType = typeof command === "string" ? "lua_script" : "json_action";
    const commandContent = typeof command === "string" ? command : JSON.stringify(command);
    const commandObj = { type: "execute", payload: command }; let successCount = 0;
    clients.forEach((c, id) => { if (pendingCommands.has(id)) { pendingCommands.get(id).push(commandObj); successCount++ } });
    try { await dbPool.query("INSERT INTO commands (command_type, content) VALUES (?, ?)", [commandType, commandContent]); } catch (error) { console.error("[DB] Failed to log command:", error.message) }
    res.json({ message: `Command broadcasted to ${successCount}/${clients.size} clients.` })
});

app.post('/announce', authenticateSession, (req, res) => {
    const { message } = req.body; if (!message) return res.status(400).json({ error: 'Missing "message"' });
    const commandObj = { type: "announce", payload: message }; let successCount = 0;
    clients.forEach((c, id) => { if (pendingCommands.has(id)) { pendingCommands.get(id).push(commandObj); successCount++ } });
    res.json({ message: `Announcement sent to ${successCount}/${clients.size} clients.` })
});

app.post('/kick', authenticateSession, (req, res) => {
    const { clientId } = req.body; if (!clientId) return res.status(400).json({ error: 'Missing "clientId".' });
    const client = clients.get(clientId); if (!client) return res.status(404).json({ error: "Client not found." });
    if (pendingCommands.has(clientId)) { pendingCommands.get(clientId).push({ type: "kick", payload: { message: "Kicked by admin." } }) }
    setTimeout(() => { clients.delete(clientId); pendingCommands.delete(clientId); }, 5000);
    res.json({ message: `Client ${client.username} kicked.` })
});

app.get('/api/executions', authenticateSession, async (req, res) => {
    try {
        const [rows] = await dbPool.query(`SELECT DATE(connected_at) AS date, COUNT(id) AS count FROM connections WHERE connected_at >= CURDATE() - INTERVAL 30 DAY GROUP BY DATE(connected_at) ORDER BY date ASC;`);
        const resultsMap = new Map(rows.map(r => [new Date(r.date).toISOString().slice(0, 10), r.count]));
        const finalData = Array.from({ length: 30 }, (_, i) => { const date = new Date(); date.setDate(date.getDate() - (29 - i)); const dateString = date.toISOString().slice(0, 10); return { date: dateString, count: resultsMap.get(dateString) || 0 }; });
        res.json(finalData);
    } catch (error) { res.status(500).json({ error: "Failed to retrieve execution statistics." }) }
});

app.get('/api/player-stats', authenticateSession, async (req, res) => {
    try {
        const [rows] = await dbPool.query(`SELECT DATE(created_at) AS date, MAX(player_count) AS count FROM player_snapshots WHERE created_at >= CURDATE() - INTERVAL 30 DAY GROUP BY DATE(created_at) ORDER BY date ASC;`);
        const resultsMap = new Map(rows.map(r => [new Date(r.date).toISOString().slice(0, 10), r.count]));
        const finalData = Array.from({ length: 30 }, (_, i) => { const date = new Date(); date.setDate(date.getDate() - (29 - i)); const dateString = date.toISOString().slice(0, 10); return { date: dateString, count: parseInt(resultsMap.get(dateString) || 0, 10) }; });
        res.json(finalData);
    } catch (error) { res.status(500).json({ error: 'Failed to retrieve weekly player statistics.' }); }
});

app.post('/admin/add-user', authenticateSession, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password required' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await dbPool.query("INSERT INTO adminusers (username, password_hash) VALUES (?, ?)", [username, hashedPassword]);
        res.json({ success: true, message: 'User added successfully' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            res.status(400).json({ success: false, message: 'Username already exists' });
        } else {
            console.error('Error adding user:', error);
            res.status(500).json({ success: false, message: 'Internal server error' });
        }
    }
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
    const playerCount = clients.size;
    if (playerCount > 0) {
        try { await dbPool.query("INSERT INTO player_snapshots (player_count) VALUES (?)", [playerCount]); } catch (error) { console.error("[DB] Failed to log player snapshot:", error.message) }
    }
}, SNAPSHOT_INTERVAL_MS);

setInterval(async () => {
    try {
        const [result] = await dbPool.query("DELETE FROM sessions WHERE expires_at < NOW()");
        if (result.affectedRows > 0) {
            console.log(`Cleaned up ${result.affectedRows} expired sessions`);
        }
    } catch (error) {
        console.error('Session cleanup error:', error);
    }
}, 60 * 60 * 1000);

// --- START SERVER ---
async function startServer() {
    await initializeDatabase();
    app.listen(PORT, () => console.log(`Aperture Command Server running on port ${PORT}`));
}

startServer();

