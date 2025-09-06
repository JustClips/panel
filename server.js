// Rolbox Command Server - Updated for Roblox Executor-Compatible Polling
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();

const PORT = process.env.PORT || 3000;

// --- Middleware ---
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

/*
    CLIENT TRACKING AND COMMAND QUEUES
    - clients: holds basic client info
    - pendingCommands: holds arrays of commands for each client
*/
let clients = new Map();
let pendingCommands = new Map();

// --- API Endpoints ---

// Health check endpoint
app.get('/', (req, res) => {
    res.json({
        message: 'Rolbox Command Server is running!',
        clientsConnected: clients.size,
    });
});

/**
 * Endpoint for clients to register.
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

    // Register client
    clients.set(id, {
        id,
        username,
        gameName,
        serverInfo,
        connectedAt: new Date()
    });
    // Ensure client has a pending command queue
    if (!pendingCommands.has(id)) pendingCommands.set(id, []);

    console.log(`Client registered: ${username} (ID: ${id}) from ${gameName}`);

    res.json({
        type: 'connected',
        clientId: id,
        message: 'Successfully registered with command server'
    });
});

/**
 * Polling endpoint for Roblox clients.
 * Clients should POST their id to get any queued commands.
 * Server replies with and clears all pending commands.
 */
app.post('/poll', (req, res) => {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: "Missing id" });

    if (!clients.has(id)) {
        return res.status(404).json({ error: `Client ${id} not registered.` });
    }

    let commands = pendingCommands.get(id) || [];
    pendingCommands.set(id, []); // Clear queue after sending

    res.json({ commands });
});

/**
 * Broadcast a command to all connected clients.
 * Example body:
 *   { "command": { "action": "show_message", "title": "...", "text": "..." } }
 */
app.post('/broadcast', (req, res) => {
    const { command } = req.body;
    if (!command) {
        return res.status(400).json({ error: 'Missing "command" in request body' });
    }

    let successCount = 0;
    clients.forEach((client, id) => {
        if (!pendingCommands.has(id)) pendingCommands.set(id, []);
        pendingCommands.get(id).push({ type: 'execute', payload: command });
        successCount++;
    });

    console.log(`Broadcasted command to ${successCount} clients:`, command);
    res.json({
        message: `Command broadcasted to ${successCount}/${clients.size} clients`,
        command
    });
});

/**
 * Send an announcement to all clients.
 * Example body:
 *   { "message": "Server maintenance soon!" }
 */
app.post('/announce', (req, res) => {
    const { message } = req.body;
    if (!message) {
        return res.status(400).json({ error: 'Missing "message" in request body' });
    }

    let successCount = 0;
    clients.forEach((client, id) => {
        if (!pendingCommands.has(id)) pendingCommands.set(id, []);
        pendingCommands.get(id).push({ type: 'announce', payload: message });
        successCount++;
    });

    console.log(`Announcement sent to ${successCount} clients:`, message);
    res.json({
        message: `Announcement sent to ${successCount}/${clients.size} clients`,
        announcement: message
    });
});

/**
 * Kick a specific client by their ID.
 * Example body:
 *   { "clientId": "executor_123456" }
 */
app.post('/kick', (req, res) => {
    const { clientId } = req.body;
    if (!clientId) {
        return res.status(400).json({ error: 'Missing "clientId" in request body' });
    }

    const client = clients.get(clientId);
    if (!client) {
        return res.status(404).json({ error: `Client ${clientId} not found.` });
    }

    // Queue kick message for client
    if (!pendingCommands.has(clientId)) pendingCommands.set(clientId, []);
    pendingCommands.get(clientId).push({ type: 'kick', payload: { message: 'You have been kicked by an admin.' } });

    clients.delete(clientId);
    pendingCommands.delete(clientId);

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
