// Rolbox Command Server - Upgraded with MySQL Persistence
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2/promise'); // Using the promise-based version of mysql2
require('dotenv').config(); // For loading environment variables from .env file

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_TIMEOUT_MS = 15000;

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

let clients = new Map();
let pendingCommands = new Map();

// --- MySQL Database Setup ---
const dbPool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Function to initialize the database and create tables if they don't exist
async function initializeDatabase() {
    try {
        const connection = await dbPool.getConnection();
        console.log('Successfully connected to MySQL database.');

        // Create the connections table for the graph statistics
        await connection.query(`
            CREATE TABLE IF NOT EXISTS connections (
                id INT AUTO_INCREMENT PRIMARY KEY,
                client_id VARCHAR(255) NOT NULL,
                username VARCHAR(255) NOT NULL,
                connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('Database tables are ready.');
        connection.release();
    } catch (error) {
        console.error('!!! DATABASE CONNECTION FAILED !!!');
        console.error('Error initializing database:', error.message);
        console.error('Please ensure your .env file is correct and the database is running.');
        process.exit(1); // Exit the application if DB connection fails
    }
}

// --- Health check endpoint ---
app.get('/', (req, res) => {
    res.json({
        message: 'Aperture Command Server is running!',
        clientsConnected: clients.size,
    });
});

// --- MODIFIED: Connect endpoint now logs to the database ---
app.post('/connect', async (req, res) => {
    const { id, username, gameName, serverInfo, playerCount, avatarUrl, userId } = req.body;
    if (!id || !username || !gameName || !serverInfo) {
        return res.status(400).json({ error: 'Bad Request: Missing required fields.' });
    }
    if (clients.has(id)) {
        return res.status(409).json({ error: `Conflict: Client with ID ${id} is already connected.` });
    }

    // Add to in-memory store
    clients.set(id, {
        id, username, userId: userId || null, gameName, serverInfo,
        playerCount: typeof playerCount === "number" ? playerCount : null,
        avatarUrl: avatarUrl || null,
        connectedAt: new Date(), lastSeen: Date.now()
    });
    if (!pendingCommands.has(id)) pendingCommands.set(id, []);
    console.log(`Client registered: ${username} (ID: ${id}) from ${gameName}`);

    // NEW: Log the connection event to the MySQL database
    try {
        await dbPool.query('INSERT INTO connections (client_id, username) VALUES (?, ?)', [id, username]);
        console.log(`[DB] Logged connection for ${username}.`);
    } catch (error) {
        console.error(`[DB] Failed to log connection for ${username}:`, error.message);
    }

    res.json({ type: 'connected', clientId: id, message: 'Successfully registered.' });
});

// --- Poll endpoint (heartbeat) ---
app.post('/poll', (req, res) => {
    const { id } = req.body;
    if (!id || !clients.has(id)) {
        return res.status(404).json({ error: `Client ${id} not registered.` });
    }
    clients.get(id).lastSeen = Date.now();
    let commands = pendingCommands.get(id) || [];
    pendingCommands.set(id, []);
    res.json({ commands });
});


// --- Broadcast, Announce, Kick (Unchanged) ---
app.post('/broadcast', (req, res) => {
    const { command } = req.body;
    if (!command) return res.status(400).json({ error: 'Missing "command"' });
    const commandObj = { type: 'execute', payload: command };
    let successCount = 0;
    clients.forEach((client, id) => {
        if (!pendingCommands.has(id)) pendingCommands.set(id, []);
        pendingCommands.get(id).push(commandObj);
        successCount++;
    });
    console.log(`Broadcasted command to ${successCount} clients.`);
    res.json({ message: `Command broadcasted to ${successCount}/${clients.size} clients` });
});

app.post('/announce', (req, res) => {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Missing "message"' });
    const commandObj = { type: 'announce', payload: message };
    let successCount = 0;
    clients.forEach((client, id) => {
        if (!pendingCommands.has(id)) pendingCommands.set(id, []);
        pendingCommands.get(id).push(commandObj);
        successCount++;
    });
    console.log(`Announcement sent to ${successCount} clients.`);
    res.json({ message: `Announcement sent to ${successCount}/${clients.size} clients` });
});

app.post('/kick', (req, res) => {
    const { clientId } = req.body;
    if (!clientId) return res.status(400).json({ error: 'Missing "clientId"' });
    const client = clients.get(clientId);
    if (!client) return res.status(404).json({ error: `Client not found.` });
    
    if (!pendingCommands.has(clientId)) pendingCommands.set(clientId, []);
    pendingCommands.get(clientId).push({ type: 'kick', payload: { message: 'Kicked by admin.' } });
    
    // Defer deletion to allow the client to poll for the kick command
    setTimeout(() => {
        clients.delete(clientId);
        pendingCommands.delete(clientId);
    }, 5000);

    console.log(`Kicked client: ${client.username} (ID: ${clientId})`);
    res.json({ message: `Client ${client.username} kicked.` });
});


// --- Admin Panel API Endpoints ---
app.get('/api/clients', (req, res) => {
    const clientList = Array.from(clients.values());
    res.json({ count: clientList.length, clients: clientList });
});

// --- NEW: API Endpoint for Graph Data ---
app.get('/api/executions', async (req, res) => {
    try {
        // This SQL query counts connections for each of the past 30 days.
        const [rows] = await dbPool.query(`
            SELECT 
                DATE(connected_at) AS date,
                COUNT(id) AS count
            FROM 
                connections
            WHERE 
                connected_at >= CURDATE() - INTERVAL 30 DAY
            GROUP BY 
                DATE(connected_at)
            ORDER BY 
                date ASC;
        `);

        // Create a map of dates to counts for easy lookup
        const resultsMap = new Map(rows.map(row => [new Date(row.date).toISOString().split('T')[0], row.count]));
        
        // Ensure all of the last 30 days are present, even if count is 0
        const finalData = [];
        for (let i = 29; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            const dateString = date.toISOString().split('T')[0];
            
            finalData.push({
                date: dateString,
                count: resultsMap.get(dateString) || 0
            });
        }

        res.json(finalData);

    } catch (error) {
        console.error('[DB] Error fetching execution stats:', error.message);
        res.status(500).json({ error: 'Failed to retrieve execution statistics.' });
    }
});


// --- Timeout Checker ---
setInterval(() => {
    const now = Date.now();
    clients.forEach((client, id) => {
        if (now - client.lastSeen > CLIENT_TIMEOUT_MS) {
            clients.delete(id);
            pendingCommands.delete(id);
            console.log(`[TIMEOUT] Kicked inactive client: ${id}`);
        }
    });
}, 5000);


// --- Start Server ---
async function startServer() {
    await initializeDatabase();
    app.listen(PORT, () => {
        console.log(`Aperture Command Server running at http://localhost:${PORT}`);
    });
}

startServer();

