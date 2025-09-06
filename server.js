// Rolbox Command Server - With Client Timeout/Heartbeat + Game Info + Avatars
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();

const PORT = process.env.PORT || 3000;
const CLIENT_TIMEOUT_MS = 15000; // 15 seconds

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

let clients = new Map();
let pendingCommands = new Map();

// Health check endpoint
app.get('/', (req, res) => {
    res.json({
        message: 'Rolbox Command Server is running!',
        clientsConnected: clients.size,
    });
});

// Connect/register endpoint (now accepts playerCount and avatarUrl)
app.post('/connect', (req, res) => {
    const { id, username, gameName, serverInfo, playerCount, avatarUrl } = req.body;
    if (!id || !username || !gameName || !serverInfo) {
        return res.status(400).json({
            error: 'Bad Request: Missing required fields (id, username, gameName, serverInfo).'
        });
    }
    if (clients.has(id)) {
        return res.status(409).json({ error: `Conflict: Client with ID ${id} is already connected.` });
    }
    clients.set(id, {
        id,
        username,
        gameName,
        serverInfo,
        playerCount: typeof playerCount === "number" ? playerCount : null,
        avatarUrl: avatarUrl || null,
        connectedAt: new Date(),
        lastSeen: Date.now()
    });
    if (!pendingCommands.has(id)) pendingCommands.set(id, []);
    console.log(`Client registered: ${username} (ID: ${id}) from ${gameName} | Players: ${playerCount || 'n/a'}`);

    res.json({
        type: 'connected',
        clientId: id,
        message: 'Successfully registered with command server'
    });
});

// Poll endpoint (heartbeat)
app.post('/poll', (req, res) => {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: "Missing id" });
    if (!clients.has(id)) {
        return res.status(404).json({ error: `Client ${id} not registered.` });
    }
    clients.get(id).lastSeen = Date.now();

    let commands = pendingCommands.get(id) || [];
    pendingCommands.set(id, []);

    res.json({ commands });
});

// Broadcast
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

// Announce
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

// Kick
app.post('/kick', (req, res) => {
    const { clientId } = req.body;
    if (!clientId) {
        return res.status(400).json({ error: 'Missing "clientId" in request body' });
    }
    const client = clients.get(clientId);
    if (!client) {
        return res.status(404).json({ error: `Client ${clientId} not found.` });
    }
    if (!pendingCommands.has(clientId)) pendingCommands.set(clientId, []);
    pendingCommands.get(clientId).push({ type: 'kick', payload: { message: 'You have been kicked by an admin.' } });

    clients.delete(clientId);
    pendingCommands.delete(clientId);

    console.log(`Kicked client: ${client.username} (ID: ${clientId})`);
    res.json({ message: `Client ${client.username} (${clientId}) has been kicked.` });
});

// --- Admin Panel API Endpoints ---

app.get('/api/status', (req, res) => {
    res.json({
        message: 'Rolbox Command Server is running!',
        clientsConnected: clients.size
    });
});
app.get('/api/clients', (req, res) => {
    const clientList = Array.from(clients.values()).map(c => ({
        id: c.id,
        username: c.username,
        gameName: c.gameName,
        serverInfo: c.serverInfo,
        playerCount: c.playerCount,
        avatarUrl: c.avatarUrl,
        connectedAt: c.connectedAt,
        lastSeen: c.lastSeen
    }));
    res.json({
        count: clientList.length,
        clients: clientList
    });
});

// --- TIMEOUT CHECKER ---
setInterval(() => {
    const now = Date.now();
    let kicked = [];
    clients.forEach((client, id) => {
        if (now - client.lastSeen > CLIENT_TIMEOUT_MS) {
            clients.delete(id);
            pendingCommands.delete(id);
            kicked.push(id);
        }
    });
    if (kicked.length > 0) {
        console.log(`[TIMEOUT] Kicked inactive clients: ${kicked.join(', ')}`);
    }
}, 5000);

// --- Error Handling ---
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

app.listen(PORT, () => {
    console.log(`Rolbox Command Server running at http://localhost:${PORT}`);
});
