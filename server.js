// Endpoint for clients to connect
app.post('/connect', (req, res) => {
    // Use the ID from the client's request body
    const { id } = req.body;

    if (!id) {
        // Reject connections that don't provide an ID
        return res.status(400).json({ error: 'Client ID ("id") is required in the request body.' });
    }

    // Check if a client with this ID is already connected
    if (clients.some(c => c.id === id)) {
        return res.status(409).json({ error: 'A client with this ID is already connected.' });
    }

    const client = {
        id: id, // Use the client-provided ID
        connectedAt: new Date(),
        response: res // This is the response object we keep open
    };
    
    clients.push(client);
    
    console.log(`Client connected: ${id}`);
    
    // Keep connection alive for long-polling
    res.writeHead(200, {
        'Content-Type': 'application/json',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache'
    });
    
    // Send initial connection confirmation
    res.write(JSON.stringify({
        type: 'connected',
        clientId: id, // Confirm the ID back to the client
        message: 'Successfully connected to command server'
    }) + '\n');
    
    // Handle client disconnect
    req.on('close', () => {
        clients = clients.filter(c => c.id !== id);
        console.log(`Client disconnected: ${id}`);
    });
    
    req.on('error', (err) => {
        console.error(`Client ${id} connection error:`, err);
        clients = clients.filter(c => c.id !== id);
    });
});
