const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const axios = require('axios');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Railway provides the PORT environment variable
const PORT = process.env.PORT || 3001;
const ROLBOX_SERVER_URL = 'https://panel-production-23ca.up.railway.app';

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Serve the main admin panel page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// API endpoint to get server status
app.get('/api/status', async (req, res) => {
  try {
    const response = await axios.get(`${ROLBOX_SERVER_URL}/`);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch server status' });
  }
});

// API endpoint to get connected clients
app.get('/api/clients', async (req, res) => {
  try {
    const response = await axios.get(`${ROLBOX_SERVER_URL}/clients`);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch clients' });
  }
});

// Handle WebSocket connections
io.on('connection', (socket) => {
  console.log('Admin panel connected');
  
  // Send initial data
  sendServerData(socket);
  
  // Handle announcement requests
  socket.on('sendAnnouncement', async (data) => {
    try {
      const response = await axios.post(`${ROLBOX_SERVER_URL}/announce`, {
        message: data.message
      });
      socket.emit('announcementSent', response.data);
    } catch (error) {
      socket.emit('error', { message: 'Failed to send announcement' });
    }
  });
  
  // Handle command requests
  socket.on('sendCommand', async (data) => {
    try {
      const response = await axios.post(`${ROLBOX_SERVER_URL}/broadcast`, {
        command: data.command
      });
      socket.emit('commandSent', response.data);
    } catch (error) {
      socket.emit('error', { message: 'Failed to send command' });
    }
  });
  
  // Handle kick requests
  socket.on('kickPlayer', async (data) => {
    try {
      const response = await axios.post(`${ROLBOX_SERVER_URL}/kick`, {
        clientId: data.clientId
      });
      socket.emit('playerKicked', response.data);
    } catch (error) {
      socket.emit('error', { message: 'Failed to kick player' });
    }
  });
  
  // Handle disconnection
  socket.on('disconnect', () => {
    console.log('Admin panel disconnected');
  });
});

// Function to send server data to clients
async function sendServerData(socket) {
  try {
    const statusResponse = await axios.get(`${ROLBOX_SERVER_URL}/`);
    const clientsResponse = await axios.get(`${ROLBOX_SERVER_URL}/clients`);
    
    socket.emit('serverData', {
      status: statusResponse.data,
      clients: clientsResponse.data
    });
  } catch (error) {
    socket.emit('error', { message: 'Failed to fetch server data' });
  }
}

// Periodically send updated server data to all clients
setInterval(() => {
  io.emit('updateRequest');
}, 5000);

// Start server
server.listen(PORT, () => {
  console.log(`Rolbox Admin Panel running on port ${PORT}`);
  console.log(`Access the panel at http://localhost:${PORT}`);
});
