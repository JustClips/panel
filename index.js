// Rolbox Command Server - Upgraded with MySQL Persistence & Proper Analytics
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_TIMEOUT_MS = 15000; // 15 seconds
const SNAPSHOT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

app.use(cors());
app.use(bodyParser.json({ limit: '5mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '5mb' }));

// In-memory stores for active connections
let clients = new Map();
let pendingCommands = new Map();

// --- MySQL Database Setup ---
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

// --- Database Initialization ---
async function initializeDatabase() {
    try {
        const connection = await dbPool.getConnection();
        console.log('Successfully connected to MySQL database.');

        // 1. Create/Update 'connections' table
        await connection.query(`
            CREATE TABLE IF NOT EXISTS connections (
                id INT AUTO_INCREMENT PRIMARY KEY,
                client_id VARCHAR(255) NOT NULL,
                username VARCHAR(255) NOT NULL,
                user_id BIGINT,
                game_name VARCHAR(255),
                server_info VARCHAR(255),
                player_count INT,
                connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('`connections` table is OK.');

        // 2. Create 'commands' table for logging executions
        await connection.query(`
            CREATE TABLE IF NOT EXISTS commands (
                id INT AUTO_INCREMENT PRIMARY KEY,
                command_type VARCHAR(50) NOT NULL,
                content TEXT,
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('`commands` table is OK.');

        // 3. Create 'player_snapshots' table for historical player counts
        await connection.query(`
            CREATE TABLE IF NOT EXISTS player_snapshots (
                id INT AUTO_INCREMENT PRIMARY KEY,
                player_count INT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('`player_snapshots` table is OK.');

        // --- Schema Migrations (for users with old table versions) ---
        const [cols] = await connection.query("SHOW COLUMNS FROM `connections`");
        const colNames = cols.map(c => c.Field);
        if (!colNames.includes('player_count')) {
            console.log('Updating `connections`: Adding `player_count` column...');
            await connection.query('ALTER TABLE `connections` ADD COLUMN `player_count` INT DEFAULT 0;');
        }
        if (!colNames.includes('game_name')) {
            console.log('Updating `connections`: Adding `game_name` column...');
            await connection.query('ALTER TABLE `connections` ADD COLUMN `game_name` VARCHAR(255);');
        }
        if (!colNames.includes('server_info')) {
            console.log('Updating `connections`: Adding `server_info` column...');
            await connection.query('ALTER TABLE `connections` ADD COLUMN `server_info` VARCHAR(255);');
        }
         if (!colNames.includes('user_id')) {
            console.log('Updating `connections`: Adding `user_id` column...');
            await connection.query('ALTER TABLE `connections` ADD COLUMN `user_id` BIGINT;');
        }

        connection.release();
        console.log('Database initialization complete.');
    } catch (error) {
        console.error('!!! DATABASE INITIALIZATION FAILED !!!', error.message);
        process.exit(1);
    }
}


// --- API Endpoints ---

// Health check
app.get('/', (req, res) => {
    res.json({ message: 'Aperture Command Server is running!', clientsConnected: clients.size });
});

// Client connects and registers itself
app.post('/connect', async (req, res) => {
    const { id, username, gameName, serverInfo, playerCount, avatarUrl, userId } = req.body;
    if (!id || !username || !gameName || !serverInfo) {
        return res.status(400).json({ error: 'Bad Request: Missing required fields.' });
    }
    
    // Update last seen time if client is already connected
    if (clients.has(id)) {
        clients.get(id).lastSeen = Date.now();
        return res.status(200).json({ type: 'reconnected', clientId: id, message: 'Heartbeat updated.' });
    }

    const clientData = {
        id, username, userId: userId || null, gameName, serverInfo,
        playerCount: typeof playerCount === "number" ? playerCount : null,
        avatarUrl: avatarUrl || null,
        connectedAt: new Date(), lastSeen: Date.now()
    };
    clients.set(id, clientData);
    if (!pendingCommands.has(id)) pendingCommands.set(id, []);
    console.log(`[CONNECT] Client registered: ${username} (ID: ${id})`);

    // Log connection to the database
    try {
        await dbPool.query(
            'INSERT INTO connections (client_id, username, user_id, game_name, server_info, player_count) VALUES (?, ?, ?, ?, ?, ?)',
            [id, username, clientData.userId, gameName, serverInfo, clientData.playerCount]
        );
        console.log(`[DB] Logged connection for ${username}.`);
    } catch (error) {
        console.error(`[DB] Failed to log connection for ${username}:`, error.message);
    }

    res.json({ type: 'connected', clientId: id, message: 'Successfully registered.' });
});

// Client polls for new commands
app.post('/poll', (req, res) => {
    const { id } = req.body;
    if (!id || !clients.has(id)) {
        return res.status(404).json({ error: `Client ${id} not registered.` });
    }
    clients.get(id).lastSeen = Date.now();
    const commands = pendingCommands.get(id) || [];
    pendingCommands.set(id, []); // Clear commands after sending
    res.json({ commands });
});

// Broadcast a command to all clients
app.post('/broadcast', async (req, res) => {
    const { command } = req.body;
    if (!command) return res.status(400).json({ error: 'Missing "command"' });
    
    const commandType = typeof command === 'string' ? 'lua_script' : 'json_action';
    const commandContent = typeof command === 'string' ? command : JSON.stringify(command);
    const commandObj = { type: 'execute', payload: command };
    
    let successCount = 0;
    clients.forEach((c, id) => {
        if(pendingCommands.has(id)) {
            pendingCommands.get(id).push(commandObj);
            successCount++;
        }
    });

    // Log the command to the database
    try {
        await dbPool.query(
            'INSERT INTO commands (command_type, content) VALUES (?, ?)',
            [commandType, commandContent]
        );
        console.log(`[DB] Logged command execution.`);
    } catch (error) {
        console.error('[DB] Failed to log command:', error.message);
    }

    console.log(`Broadcasted command to ${successCount} clients.`);
    res.json({ message: `Command broadcasted to ${successCount}/${clients.size} clients.` });
});

// Send an announcement to all clients
app.post('/announce', (req, res) => {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Missing "message"' });
    const commandObj = { type: 'announce', payload: message };
    let successCount = 0;
    clients.forEach((c, id) => {
        if(pendingCommands.has(id)) {
            pendingCommands.get(id).push(commandObj);
            successCount++;
        }
    });
    console.log(`Announced to ${successCount} clients.`);
    res.json({ message: `Announcement sent to ${successCount}/${clients.size} clients.` });
});

// Kick a specific client
app.post('/kick', (req, res) => {
    const { clientId } = req.body;
    if (!clientId) return res.status(400).json({ error: 'Missing "clientId".' });
    const client = clients.get(clientId);
    if (!client) return res.status(404).json({ error: 'Client not found.' });

    if(pendingCommands.has(clientId)) {
        pendingCommands.get(clientId).push({ type: 'kick', payload: { message: 'Kicked by admin.' } });
    }
    
    // Remove after a delay to ensure the kick command is received
    setTimeout(() => {
        clients.delete(clientId);
        pendingCommands.delete(clientId);
        console.log(`Client removed: ${client.username} (ID: ${clientId})`);
    }, 5000);

    console.log(`Sent kick command to: ${client.username}`);
    res.json({ message: `Client ${client.username} kicked.` });
});

// --- Admin Panel API Endpoints ---
app.get('/api/clients', (req, res) => {
    res.json({ count: clients.size, clients: Array.from(clients.values()) });
});

// Endpoint for the "Commands Per Day" chart
app.get('/api/executions', async (req, res) => {
    try {
        const [rows] = await dbPool.query(`
            SELECT DATE(executed_at) AS date, COUNT(id) AS count 
            FROM commands
            WHERE executed_at >= CURDATE() - INTERVAL 30 DAY
            GROUP BY DATE(executed_at) 
            ORDER BY date ASC;
        `);
        const resultsMap = new Map(rows.map(r => [new Date(r.date).toISOString().slice(0, 10), r.count]));
        const finalData = Array.from({ length: 30 }, (_, i) => {
            const date = new Date();
            date.setDate(date.getDate() - (29 - i));
            const dateString = date.toISOString().slice(0, 10);
            return { date: dateString, count: resultsMap.get(dateString) || 0 };
        });
        res.json(finalData);
    } catch (error) {
        console.error('Error fetching execution stats:', error.message);
        res.status(500).json({ error: 'Failed to retrieve execution statistics.' });
    }
});

// Endpoint for the "Daily Peak Players" chart
app.get('/api/players-weekly', async (req, res) => {
    try {
        const [rows] = await dbPool.query(`
            SELECT DATE(created_at) AS date, MAX(player_count) AS count 
            FROM player_snapshots
            WHERE created_at >= CURDATE() - INTERVAL 7 DAY
            GROUP BY DATE(created_at) 
            ORDER BY date ASC;
        `);
        const resultsMap = new Map(rows.map(r => [new Date(r.date).toISOString().slice(0, 10), r.count]));
        const finalData = Array.from({ length: 7 }, (_, i) => {
            const date = new Date();
            date.setDate(date.getDate() - (6 - i));
            const dateString = date.toISOString().slice(0, 10);
            return { date: dateString, count: parseInt(resultsMap.get(dateString) || 0, 10) };
        });
        res.json(finalData);
    } catch (error) {
        console.error('Error fetching weekly player stats:', error.message);
        res.status(500).json({ error: 'Failed to retrieve weekly player statistics.' });
    }
});

// --- Utility Functions ---

// Periodically remove clients that haven't polled recently
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

// Periodically log the current player count
setInterval(async () => {
    const playerCount = clients.size;
    if (playerCount > 0) {
        try {
            await dbPool.query(
                'INSERT INTO player_snapshots (player_count) VALUES (?)', 
                [playerCount]
            );
            console.log(`[DB] Logged player snapshot: ${playerCount} players.`);
        } catch (error) {
            console.error('[DB] Failed to log player snapshot:', error.message);
        }
    }
}, SNAPSHOT_INTERVAL_MS);


// --- Start Server ---
async function startServer() {
    await initializeDatabase();
    app.listen(PORT, () => console.log(`Aperture Command Server running on port ${PORT}`));
}

startServer();
