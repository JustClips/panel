// Rolbox Command Server - Upgraded with MySQL Persistence & Proper Analytics
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_TIMEOUT_MS = 15000; // 15 seconds
const SNAPSHOT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

// --- MIDDLEWARE & CONFIG ---
app.use(cors()); // Allow all origins for simplicity
app.use(bodyParser.json({ limit: '5mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '5mb' }));

// In-memory stores for active connections
let clients = new Map();
let pendingCommands = new Map();

// Generate session ID
function generateSessionId() {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
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

        await connection.query(`CREATE TABLE IF NOT EXISTS connections (id INT AUTO_INCREMENT PRIMARY KEY, client_id VARCHAR(255) NOT NULL, username VARCHAR(255) NOT NULL, user_id BIGINT, game_name VARCHAR(255), server_info VARCHAR(255), player_count INT, connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS commands (id INT AUTO_INCREMENT PRIMARY KEY, command_type VARCHAR(50) NOT NULL, content TEXT, executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS player_snapshots (id INT AUTO_INCREMENT PRIMARY KEY, player_count INT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS sessions (session_id VARCHAR(255) PRIMARY KEY, user_id INT NOT NULL, username VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, expires_at TIMESTAMP NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);`);

        // Check and add columns to connections table if they don't exist
        const [cols] = await connection.query("SHOW COLUMNS FROM `connections`");
        const colNames = cols.map(c => c.Field);
        if (!colNames.includes("player_count")) { await connection.query("ALTER TABLE `connections` ADD COLUMN `player_count` INT DEFAULT 0;"); }
        if (!colNames.includes("game_name")) { await connection.query("ALTER TABLE `connections` ADD COLUMN `game_name` VARCHAR(255);"); }
        if (!colNames.includes("server_info")) { await connection.query("ALTER TABLE `connections` ADD COLUMN `server_info` VARCHAR(255);"); }
        if (!colNames.includes("user_id")) { await connection.query("ALTER TABLE `connections` ADD COLUMN `user_id` BIGINT;"); }

        // Create default users if they don't exist
        const [users] = await connection.query("SELECT COUNT(*) as count FROM users");
        if (users[0].count === 0) {
            console.log("Creating default users...");
            const hashedVupxy = await bcrypt.hash('vupxydev', 10);
            const hashedMegamind = await bcrypt.hash('megaminddev', 10);
            await connection.query("INSERT INTO users (username, password_hash) VALUES (?, ?), (?, ?)",
                ['vupxy', hashedVupxy, 'megamind', hashedMegamind]);
            console.log("Default users created: vupxy, megamind");
        }

        connection.release();
        console.log("Database initialization complete.");
    } catch (error) {
        console.error("!!! DATABASE INITIALIZATION FAILED !!!", error.message);
        process.exit(1);
    }
}

// --- AUTHENTICATION MIDDLEWARE ---
const authenticateSession = async (req, res, next) => {
    const sessionId = req.headers['x-session-id'];
    if (!sessionId) {
        return res.status(401).json({ success: false, message: 'Unauthorized: No session ID provided' });
    }

    try {
        const connection = await dbPool.getConnection();
        const [rows] = await connection.query(
            "SELECT s.*, u.username FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.session_id = ? AND s.expires_at > NOW()",
            [sessionId]
        );
        connection.release();

        if (rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Unauthorized: Invalid or expired session' });
        }

        const session = rows[0];
        req.user = { id: session.user_id, name: session.username };
        next(); // Session is valid, proceed
    } catch (error) {
        console.error('Session validation error:', error);
        return res.status(500).json({ success: false, message: 'Internal server error' });
    }
};

// --- API ENDPOINTS ---

// --- PUBLIC ENDPOINTS ---

app.get('/', (req, res) => {
    res.json({ message: 'Aperture Command Server is running!', clientsConnected: clients.size });
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required.' });
    }

    try {
        const connection = await dbPool.getConnection();
        const [rows] = await connection.query("SELECT * FROM users WHERE username = ?", [username]);

        if (rows.length === 0) {
            connection.release();
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (isMatch) {
            // Create a new session for this login
            const sessionId = generateSessionId();
            const expiresAt = new Date(Date.now() + (8 * 60 * 60 * 1000)); // 8 hours

            // This allows multiple sessions for the same user
            await connection.query(
                "INSERT INTO sessions (session_id, user_id, username, expires_at) VALUES (?, ?, ?, ?)",
                [sessionId, user.id, user.username, expiresAt]
            );
            connection.release();

            console.log('Login successful for:', username);
            res.json({ success: true, sessionId: sessionId, username: user.username });
        } else {
            connection.release();
            console.log('Invalid password for user:', username);
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/logout', async (req, res) => {
    const sessionId = req.headers['x-session-id'];
    if (!sessionId) {
        return res.status(400).json({ success: false, message: 'No session ID provided' });
    }

    try {
        const connection = await dbPool.getConnection();
        const [result] = await connection.query("DELETE FROM sessions WHERE session_id = ?", [sessionId]);
        connection.release();

        if (result.affectedRows > 0) {
            res.json({ success: true, message: 'Logged out successfully' });
        } else {
            res.status(400).json({ success: false, message: 'Invalid session' });
        }
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/test-system', async (req, res) => {
    try {
        const connection = await dbPool.getConnection();
        const [users] = await connection.query("SELECT username FROM users");
        connection.release();

        res.json({
            message: 'System is working!',
            user_count: users.length,
            users: users.map(u => u.username)
        });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});


// --- GAME CLIENT ENDPOINTS ---

app.post('/connect', async (req, res) => {
    const { id, username, gameName, serverInfo, playerCount, avatarUrl, userId } = req.body;
    if (!id || !username || !gameName || !serverInfo) {
        return res.status(400).json({ error: "Bad Request: Missing required fields." });
    }
    if (clients.has(id)) {
        clients.get(id).lastSeen = Date.now();
        return res.status(200).json({ type: "reconnected", clientId: id, message: "Heartbeat updated." });
    }
    const clientData = { id, username, userId: userId || null, gameName, serverInfo, playerCount: typeof playerCount === "number" ? playerCount : null, avatarUrl: avatarUrl || null, connectedAt: new Date(), lastSeen: Date.now() };
    clients.set(id, clientData);
    if (!pendingCommands.has(id)) {
        pendingCommands.set(id, []);
    }
    console.log(`[CONNECT] Client registered: ${username} (ID: ${id})`);
    try {
        await dbPool.query("INSERT INTO connections (client_id, username, user_id, game_name, server_info, player_count) VALUES (?, ?, ?, ?, ?, ?)", [id, username, clientData.userId, gameName, serverInfo, clientData.playerCount]);
        console.log(`[DB] Logged connection for ${username}.`);
    } catch (error) {
        console.error(`[DB] Failed to log connection for ${username}:`, error.message);
    }
    res.json({ type: "connected", clientId: id, message: "Successfully registered." });
});

app.post('/poll', (req, res) => {
    const { id } = req.body;
    if (!id || !clients.has(id)) {
        return res.status(404).json({ error: `Client ${id} not registered.` });
    }
    clients.get(id).lastSeen = Date.now();
    const commands = pendingCommands.get(id) || [];
    pendingCommands.set(id, []);
    res.json({ commands });
});

// --- PROTECTED ADMIN ENDPOINTS ---

app.post('/broadcast', authenticateSession, async (req, res) => {
    const { command } = req.body;
    if (!command) return res.status(400).json({ error: 'Missing "command"' });
    const commandType = typeof command === "string" ? "lua_script" : "json_action";
    const commandContent = typeof command === "string" ? command : JSON.stringify(command);
    const commandObj = { type: "execute", payload: command };
    let successCount = 0;
    clients.forEach((c, id) => {
        if (pendingCommands.has(id)) {
            pendingCommands.get(id).push(commandObj);
            successCount++;
        }
    });
    try {
        await dbPool.query("INSERT INTO commands (command_type, content) VALUES (?, ?)", [commandType, commandContent]);
        console.log("[DB] Logged command execution.");
    } catch (error) {
        console.error("[DB] Failed to log command:", error.message);
    }
    console.log(`Broadcasted command to ${successCount} clients.`);
    res.json({ message: `Command broadcasted to ${successCount}/${clients.size} clients.` });
});

app.post('/announce', authenticateSession, (req, res) => {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Missing "message"' });
    const commandObj = { type: "announce", payload: message };
    let successCount = 0;
    clients.forEach((c, id) => {
        if (pendingCommands.has(id)) {
            pendingCommands.get(id).push(commandObj);
            successCount++;
        }
    });
    console.log(`Announced to ${successCount} clients.`);
    res.json({ message: `Announcement sent to ${successCount}/${clients.size} clients.` });
});

app.post('/kick', authenticateSession, (req, res) => {
    const { clientId } = req.body;
    if (!clientId) return res.status(400).json({ error: 'Missing "clientId".' });
    const client = clients.get(clientId);
    if (!client) return res.status(404).json({ error: "Client not found." });
    if (pendingCommands.has(clientId)) {
        pendingCommands.get(clientId).push({ type: "kick", payload: { message: "Kicked by admin." } });
    }
    setTimeout(() => {
        clients.delete(clientId);
        pendingCommands.delete(clientId);
        console.log(`Client removed: ${client.username} (ID: ${clientId})`);
    }, 5000);
    console.log(`Sent kick command to: ${client.username}`);
    res.json({ message: `Client ${client.username} kicked.` });
});

app.get('/api/clients', authenticateSession, (req, res) => {
    res.json({ count: clients.size, clients: Array.from(clients.values()) });
});

app.get('/api/executions', authenticateSession, async (req, res) => {
    try {
        const [rows] = await dbPool.query(`SELECT DATE(connected_at) AS date, COUNT(id) AS count FROM connections WHERE connected_at >= CURDATE() - INTERVAL 30 DAY GROUP BY DATE(connected_at) ORDER BY date ASC;`);
        const resultsMap = new Map(rows.map(r => [new Date(r.date).toISOString().slice(0, 10), r.count]));
        const finalData = Array.from({ length: 30 }, (_, i) => {
            const date = new Date();
            date.setDate(date.getDate() - (29 - i));
            const dateString = date.toISOString().slice(0, 10);
            return { date: dateString, count: resultsMap.get(dateString) || 0 };
        });
        res.json(finalData);
    } catch (error) {
        console.error("Error fetching execution stats:", error.message);
        res.status(500).json({ error: "Failed to retrieve execution statistics." });
    }
});

app.get('/api/player-stats', authenticateSession, async (req, res) => {
    try {
        const [rows] = await dbPool.query(`
            SELECT DATE(created_at) AS date, MAX(player_count) AS count 
            FROM player_snapshots
            WHERE created_at >= CURDATE() - INTERVAL 30 DAY
            GROUP BY DATE(created_at) 
            ORDER BY date ASC;
        `);
        const resultsMap = new Map(rows.map(r => [new Date(r.date).toISOString().slice(0, 10), r.count]));
        const finalData = Array.from({ length: 30 }, (_, i) => {
            const date = new Date();
            date.setDate(date.getDate() - (29 - i));
            const dateString = date.toISOString().slice(0, 10);
            return { date: dateString, count: parseInt(resultsMap.get(dateString) || 0, 10) };
        });
        res.json(finalData);
    } catch (error) {
        console.error('Error fetching weekly player stats:', error.message);
        res.status(500).json({ error: 'Failed to retrieve weekly player statistics.' });
    }
});

app.post('/admin/add-user', authenticateSession, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const connection = await dbPool.getConnection();
        await connection.query("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, hashedPassword]);
        connection.release();

        console.log(`Admin added new user: ${username}`);
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

// Kick inactive clients
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

// Log player count snapshot
setInterval(async () => {
    const playerCount = clients.size;
    if (playerCount > 0) {
        try {
            await dbPool.query("INSERT INTO player_snapshots (player_count) VALUES (?)", [playerCount]);
            console.log(`[DB] Logged player snapshot: ${playerCount} players.`);
        } catch (error) {
            console.error("[DB] Failed to log player snapshot:", error.message);
        }
    }
}, SNAPSHOT_INTERVAL_MS);

// Cleanup expired sessions
setInterval(async () => {
    try {
        const connection = await dbPool.getConnection();
        const [result] = await connection.query("DELETE FROM sessions WHERE expires_at < NOW()");
        connection.release();
        if (result.affectedRows > 0) {
            console.log(`Cleaned up ${result.affectedRows} expired sessions`);
        }
    } catch (error) {
        console.error('Session cleanup error:', error);
    }
}, 60 * 60 * 1000); // Check every hour

// --- START SERVER ---
async function startServer() {
    await initializeDatabase();
    app.listen(PORT, () => console.log(`Aperture Command Server running on port ${PORT}`));
}

startServer();
