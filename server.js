const WebSocket = require('ws');

const wss = new WebSocket.Server({ port: 8080 });

// Use an object to store info about each server, using its unique JobId as the key
const serverRegistry = {};

// This function sends the updated server list to everyone
function broadcastServerList() {
    const serverList = Object.values(serverRegistry);
    const message = JSON.stringify({
        type: 'serverListUpdate',
        payload: serverList
    });

    for (const ws of wss.clients) {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(message);
        }
    }
    console.log('Broadcasted server list update.');
}

wss.on('connection', (ws) => {
    console.log('✅ A client has connected.');
    let serverJobId = null; // To track which server this connection belongs to

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            
            // --- Message Handling ---
            switch (data.type) {
                // When a new server comes online, it registers itself
                case 'register':
                    serverJobId = data.payload.jobId;
                    serverRegistry[serverJobId] = {
                        jobId: serverJobId,
                        placeId: data.payload.placeId,
                        playerCount: data.payload.playerCount,
                        maxPlayers: data.payload.maxPlayers,
                        uptime: 0
                    };
                    console.log(`Server registered: ${serverJobId}`);
                    broadcastServerList(); // Send the new list to everyone
                    break;

                // A server sends periodic updates with its player count
                case 'update':
                    if (serverJobId && serverRegistry[serverJobId]) {
                        serverRegistry[serverJobId].playerCount = data.payload.playerCount;
                        serverRegistry[serverJobId].uptime = data.payload.uptime;
                        // Don't broadcast on every single update to avoid spam,
                        // the main broadcast happens when servers join/leave.
                        // You could add a timer to broadcast every 5 seconds if needed.
                    }
                    break;
                
                // An admin sends a command to be broadcasted
                case 'announcement':
                case 'kick':
                    console.log(`Broadcasting command: ${data.type}`);
                    // Re-wrap the command and send it to all servers
                    const commandMessage = JSON.stringify(data);
                    for (const client of wss.clients) {
                        if (client.readyState === WebSocket.OPEN) {
                            client.send(commandMessage);
                        }
                    }
                    break;
            }
        } catch (error) {
            console.error('Error processing message:', error);
        }
    });

    ws.on('close', () => {
        console.log(`❌ Client disconnected.`);
        if (serverJobId && serverRegistry[serverJobId]) {
            console.log(`Server unregistered: ${serverJobId}`);
            delete serverRegistry[serverJobId];
            broadcastServerList(); // A server left, so update everyone
        }
    });

    ws.on('error', (error) => console.error('WebSocket error:', error));
});

console.log('🚀 Enhanced WebSocket server is running on ws://localhost:8080');
