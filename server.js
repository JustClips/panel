const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = 'path'; // Node.js path module
const app = express();

// Railway provides the PORT environment variable
const PORT = process.env.PORT || 3000;

// --- Middleware ---
app.use(cors()); // Enable Cross-Origin Resource Sharing
app.use(bodyParser.json()); // Parse JSON bodies
app.use(bodyParser.urlencoded({ extended: true })); // Parse URL-encoded bodies

// --- In-memory storage ---
// We use a Map for more efficient client lookups and deletions
let clients = new Map();

// --- API Endpoints ---

// Health check endpoint
app.get('/', (req, res) => {
    res.json({
        message: 'Rolbox Command Server is running!',
        clientsConnected: clients.size,
    });
});

/**
 * Endpoint for clients to connect.
 * This uses long-polling to keep the connection open for real-time commands.
 *
 * EXPECTED BODY:
 * {
 * "id": "unique_client_id_from_game",
 * "username": "PlayerUsername",
 * "gameName": "My Cool Game",
 * "serverInfo": "VIP Server #123"
 * }
 */
app.post('/connect', (req, res) => {
    const { id, username, gameName, serverInfo } = req.body;

    // Validate required fields
    if (!id || !username || !gameName || !serverInfo) {
        return res.status(400).json({
            error: 'Bad Request: Missing required fields (id, username, gameName, serverInfo).'
        });
    }

    if (clients.has(id)) {
        return res.status(409).json({ error: `Conflict: Client with ID ${id} is already connected.` });
    }

    const client = {
        id,
        username,
        gameName,
        serverInfo,
        connectedAt: new Date(),
        response: res // Store the response object to send data later
    };

    clients.set(id, client);
    console.log(`Client connected: ${username} (ID: ${id}) from ${gameName}`);

    // Set headers for a long-polling connection
    res.writeHead(200, {
        'Content-Type': 'application/json',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache'
    });

    // Send initial connection confirmation
    res.write(JSON.stringify({
        type: 'connected',
        clientId: id,
        message: 'Successfully connected to command server'
    }) + '\n');

    // Handle client disconnect (when the game client closes the connection)
    req.on('close', () => {
        clients.delete(id);
        console.log(`Client disconnected: ${username} (ID: ${id})`);
    });

    req.on('error', (err) => {
        console.error(`Connection error for client ${id}:`, err);
        clients.delete(id);
    });
});

// Endpoint to broadcast a command to all connected clients
app.post('/broadcast', (req, res) => {
    const { command } = req.body;
    if (!command) {
        return res.status(400).json({ error: 'Missing "command" in request body' });
    }

    console.log(`Broadcasting command to ${clients.size} clients: ${command}`);
    let successCount = 0;
    clients.forEach(client => {
        try {
            client.response.write(JSON.stringify({ type: 'execute', payload: command }) + '\n');
            successCount++;
        } catch (err) {
            console.error(`Failed to send command to client ${client.id}:`, err);
        }
    });

    res.json({
        message: `Command broadcasted to ${successCount}/${clients.size} clients`,
        command
    });
});

// Endpoint to send an announcement to all clients
app.post('/announce', (req, res) => {
    const { message } = req.body;
    if (!message) {
        return res.status(400).json({ error: 'Missing "message" in request body' });
    }

    console.log(`Sending announcement: ${message}`);
    let successCount = 0;
    clients.forEach(client => {
        try {
            client.response.write(JSON.stringify({ type: 'announce', payload: message }) + '\n');
            successCount++;
        } catch (err) {
            console.error(`Failed to send announcement to client ${client.id}:`, err);
        }
    });

    res.json({
        message: `Announcement sent to ${successCount}/${clients.size} clients`,
        announcement: message
    });
});


// Endpoint to kick a specific client by their ID
app.post('/kick', (req, res) => {
    const { clientId } = req.body;
    if (!clientId) {
        return res.status(400).json({ error: 'Missing "clientId" in request body' });
    }

    const client = clients.get(clientId);
    if (!client) {
        return res.status(404).json({ error: `Client ${clientId} not found.` });
    }

    try {
        // Send a kick message and then end the connection
        client.response.write(JSON.stringify({ type: 'kick', message: 'You have been kicked by an admin.' }) + '\n');
        client.response.end(); // This closes the long-polling connection
    } catch (err) {
        console.error(`Error writing kick message to client ${clientId}:`, err);
        // Ensure client is removed even if write fails
        if(client.response) client.response.end();
    }

    clients.delete(clientId); // Remove from the map
    console.log(`Kicked client: ${client.username} (ID: ${clientId})`);
    res.json({ message: `Client ${client.username} (${clientId}) has been kicked.` });
});


// --- Admin Panel API Endpoints ---

// Get server status and basic info
app.get('/api/status', (req, res) => {
    res.json({
        message: 'Rolbox Command Server is running!',
        clientsConnected: clients.size
    });
});

// Get a detailed list of all connected clients
app.get('/api/clients', (req, res) => {
    // Convert Map values to an array for the JSON response
    const clientList = Array.from(clients.values()).map(c => ({
        id: c.id,
        username: c.username,
        gameName: c.gameName,
        serverInfo: c.serverInfo,
        connectedAt: c.connectedAt
    }));
    res.json({
        count: clientList.length,
        clients: clientList
    });
});


// --- Error Handling ---
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});


// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Rolbox Command Server running at http://localhost:${PORT}`);
});
