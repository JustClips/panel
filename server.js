const WebSocket = require('ws');
const http = require('http'); // Import the http module

// Railway provides the port via an environment variable. Fallback to 3000 for local testing.
const PORT = process.env.PORT || 3000;

// Create a simple HTTP server to handle health checks
const server = http.createServer((req, res) => {
    // This is the health check endpoint. It responds to any HTTP request with "OK".
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Server is alive and listening');
});

// Attach the WebSocket server to the HTTP server
const wss = new WebSocket.Server({ server });

// This object will hold the live data for each connected server instance.
const serverRegistry = {};

/**
 * Broadcasts a message to all connected clients.
 * @param {object} messageObject The JavaScript object to send.
 */
function broadcast(messageObject) {
    const messageString = JSON.stringify(messageObject);
    for (const client of wss.clients) {
        if (client.readyState === WebSocket.OPEN) {
            client.send(messageString);
        }
    }
}

// This function specifically broadcasts the updated list of all servers.
function broadcastServerList() {
    const serverList = Object.values(serverRegistry);
    broadcast({ type: 'serverListUpdate', payload: serverList });
    console.log('Broadcasted server list update.');
}

wss.on('connection', (ws) => {
    let serverJobId = null; // Used to identify which server this connection belongs to.

    console.log('✅ A client has connected.');

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);

            // Handle different message types from Roblox
            switch (data.type) {
                // When a server first comes online
                case 'register':
                    serverJobId = data.payload.jobId;
                    serverRegistry[serverJobId] = {
                        jobId: serverJobId,
                        gameName: data.payload.gameName,
                        playerCount: data.payload.playerCount,
                        playersList: data.payload.playersList, // List of usernames
                        uptime: 0,
                    };
                    console.log(`Server registered: ${serverJobId} (${data.payload.gameName})`);
                    broadcastServerList(); // Tell all admin panels about the new server
                    break;

                // For periodic updates from an existing server
                case 'update':
                    if (serverJobId && serverRegistry[serverJobId]) {
                        serverRegistry[serverJobId].playerCount = data.payload.playerCount;
                        serverRegistry[serverJobId].playersList = data.payload.playersList;
                        serverRegistry[serverJobId].uptime = data.payload.uptime;
                        // Broadcast the new list after an update
                        broadcastServerList();
                    }
                    break;
                
                // For commands sent by an admin to be broadcasted
                case 'announcement':
                case 'kick':
                    console.log(`Broadcasting command: ${data.type}`);
                    broadcast(data); // Broadcast the entire command object
                    break;
            }
        } catch (error) {
            console.error('Failed to process message:', error);
        }
    });

    ws.on('close', () => {
        console.log(`❌ A client has disconnected.`);
        if (serverJobId && serverRegistry[serverJobId]) {
            console.log(`Server unregistered: ${serverJobId}`);
            delete serverRegistry[serverJobId];
            broadcastServerList(); // Tell all admin panels that a server has left
        }
    });

    ws.on('error', (error) => console.error('WebSocket error:', error));
});

// Start the HTTP server, which also starts the WebSocket server
server.listen(PORT, () => {
    console.log(`🚀 HTTP and WebSocket server is running on port ${PORT}`);
});
