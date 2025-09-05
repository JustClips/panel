const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON bodies and allow cross-origin requests
app.use(express.json());
app.use(cors());

// In-memory storage for server data and pending commands
const serverRegistry = new Map();
const commandQueue = [];

// This endpoint is for the Roblox game server to send its status and get commands
app.post('/api/heartbeat', (req, res) => {
    const { jobId, gameName, playerCount, playersList, uptime } = req.body;

    // Update the server's status and last seen time
    serverRegistry.set(jobId, {
        jobId,
        gameName,
        playerCount,
        playersList,
        uptime,
        lastSeen: Date.now()
    });

    console.log(`Received heartbeat from server: ${jobId}`);
    
    // Send back any commands that have been queued since the last check-in
    // and clear the queue.
    const commandsToSend = [...commandQueue];
    commandQueue.length = 0; // Clear the array

    res.json({ commands: commandsToSend });
});

// This endpoint is for your admin panel to fetch the list of active servers
app.get('/api/servers', (req, res) => {
    const activeServers = [];
    const now = Date.now();

    // A server is considered "dead" if it hasn't sent a heartbeat in 30 seconds
    const LIVENESS_THRESHOLD = 30 * 1000; 

    for (const [jobId, serverData] of serverRegistry.entries()) {
        if (now - serverData.lastSeen < LIVENESS_THRESHOLD) {
            activeServers.push(serverData);
        } else {
            // Remove dead server from the registry
            serverRegistry.delete(jobId);
        }
    }
    res.json(activeServers);
});

// This endpoint is for your admin panel to send a command
app.post('/api/command', (req, res) => {
    const { type, payload } = req.body;
    if (!type || !payload) {
        return res.status(400).json({ error: 'Invalid command format' });
    }

    const command = { type, payload, id: `cmd_${Date.now()}` };
    commandQueue.push(command); // Add command to the queue for all servers
    
    console.log(`Queued command: ${type}`, payload);
    res.status(200).json({ message: 'Command queued successfully' });
});

app.listen(PORT, () => {
    console.log(`🚀 HTTP API server is running on port ${PORT}`);
});
