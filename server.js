const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const app = express();

// Railway provides the PORT environment variable
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// In-memory storage for connected clients
let clients = [];
let clientIdCounter = 1;

// Utility function to generate unique client IDs
function generateClientId() {
  return `client_${clientIdCounter++}`;
}

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ 
    message: 'Rolbox Command Server is running!',
    clientsConnected: clients.length,
    endpoints: {
      connect: 'POST /connect',
      broadcast: 'POST /broadcast',
      announce: 'POST /announce',
      kick: 'POST /kick'
    }
  });
});

// Endpoint for clients to connect
app.post('/connect', (req, res) => {
  const clientId = generateClientId();
  const client = {
    id: clientId,
    connectedAt: new Date(),
    response: res
  };
  
  clients.push(client);
  
  console.log(`Client connected: ${clientId}`);
  
  // Keep connection alive
  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Connection': 'keep-alive',
    'Cache-Control': 'no-cache'
  });
  
  // Send initial connection confirmation
  res.write(JSON.stringify({
    type: 'connected',
    clientId: clientId,
    message: 'Successfully connected to command server'
  }) + '\n');
  
  // Handle client disconnect
  req.on('close', () => {
    clients = clients.filter(c => c.id !== clientId);
    console.log(`Client disconnected: ${clientId}`);
  });
  
  // Handle errors
  req.on('error', (err) => {
    console.error(`Client ${clientId} connection error:`, err);
    clients = clients.filter(c => c.id !== clientId);
  });
});

// Endpoint to broadcast commands to all connected clients
app.post('/broadcast', (req, res) => {
  const { command } = req.body;
  
  if (!command) {
    return res.status(400).json({ error: 'Missing command in request body' });
  }
  
  console.log(`Broadcasting command to ${clients.length} clients`);
  
  let successCount = 0;
  clients.forEach(client => {
    try {
      client.response.write(JSON.stringify({
        type: 'execute',
        payload: command
      }) + '\n');
      successCount++;
    } catch (err) {
      console.error(`Failed to send command to client ${client.id}:`, err);
    }
  });
  
  res.json({
    message: `Command broadcasted to ${successCount}/${clients.length} clients`,
    command: command
  });
});

// Endpoint to send announcements to all clients
app.post('/announce', (req, res) => {
  const { message } = req.body;
  
  if (!message) {
    return res.status(400).json({ error: 'Missing message in request body' });
  }
  
  console.log(`Sending announcement: ${message}`);
  
  let successCount = 0;
  clients.forEach(client => {
    try {
      client.response.write(JSON.stringify({
        type: 'announce',
        payload: message
      }) + '\n');
      successCount++;
    } catch (err) {
      console.error(`Failed to send announcement to client ${client.id}:`, err);
    }
  });
  
  res.json({
    message: `Announcement sent to ${successCount}/${clients.length} clients`,
    announcement: message
  });
});

// Endpoint to kick a specific client
app.post('/kick', (req, res) => {
  const { clientId } = req.body;
  
  if (!clientId) {
    return res.status(400).json({ error: 'Missing clientId in request body' });
  }
  
  const client = clients.find(c => c.id === clientId);
  if (!client) {
    return res.status(404).json({ error: `Client ${clientId} not found` });
  }
  
  try {
    client.response.write(JSON.stringify({
      type: 'kick',
      message: 'You have been kicked from the server'
    }) + '\n');
    client.response.end();
  } catch (err) {
    console.error(`Error kicking client ${clientId}:`, err);
  }
  
  clients = clients.filter(c => c.id !== clientId);
  console.log(`Kicked client: ${clientId}`);
  
  res.json({ message: `Client ${clientId} has been kicked` });
});

// Get list of connected clients
app.get('/clients', (req, res) => {
  res.json({
    count: clients.length,
    clients: clients.map(c => ({
      id: c.id,
      connectedAt: c.connectedAt
    }))
  });
});

// Admin panel endpoint
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Admin API endpoints
app.get('/api/status', (req, res) => {
  res.json({
    message: 'Rolbox Command Server is running!',
    clientsConnected: clients.length
  });
});

app.get('/api/clients', (req, res) => {
  res.json({
    count: clients.length,
    clients: clients.map(c => ({
      id: c.id,
      connectedAt: c.connectedAt
    }))
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Handle 404s
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Rolbox Command Server running on port ${PORT}`);
});
