// Import the WebSocket library
const WebSocket = require('ws');

// Create a new WebSocket server on port 8080
const wss = new WebSocket.Server({ port: 8080 });

// Use a Set to store all connected clients (Roblox game servers)
const clients = new Set();

// This runs when a new client (a Roblox server) connects
wss.on('connection', (ws) => {
    console.log('✅ A Roblox server has connected.');
    clients.add(ws);

    // This runs when the server receives a message from a client
    ws.on('message', (message) => {
        console.log('Received message =>', message.toString());

        try {
            const data = JSON.parse(message);

            // --- IMPORTANT ---
            // Add a security check here! For example, check for a secret key.
            // if (data.secret !== "YourSuperSecretKey") {
            //     console.log('Invalid secret key. Ignoring message.');
            //     return;
            // }

            // Broadcast the message to ALL connected clients
            broadcast(message.toString());

        } catch (error) {
            console.error('Failed to parse message or broadcast:', error);
        }
    });

    // This runs when a client disconnects
    ws.on('close', () => {
        console.log('❌ A Roblox server has disconnected.');
        clients.delete(ws);
    });

    // Handle any errors
    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
    });
});

/**
 * Sends a message to every connected client.
 * @param {string} message The message to send.
 */
function broadcast(message) {
    console.log('Broadcasting message to', clients.size, 'clients.');
    for (const client of clients) {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message);
        }
    }
}

console.log('🚀 WebSocket server is running on ws://localhost:8080');
