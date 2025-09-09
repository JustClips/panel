// Rolbox Command Server - Upgraded with MySQL, File Uploads & Luarmor Integration
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const multer = require('multer');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// --- SERVE FRONTEND STATIC FILES ---
app.use(express.static(path.join(__dirname, 'public')));

// --- TRUST PROXY FOR RAILWAY ---
app.set('trust proxy', 1);

// --- SECURITY & CORE MIDDLEWARE ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://challenges.cloudflare.com", "https://cdn.jsdelivr.net"],
            "style-src": ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
            "font-src": ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"],
            "img-src": ["'self'", "data:", "https://i.imgur.com"],
            "frame-src": ["'self'", "https://challenges.cloudflare.com"]
        }
    }
}));

const allowedOrigins = [
  'https://eps1llon.win',
  'https://www.eps1llon.win'
];

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.error(`CORS Blocked Origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use(bodyParser.json({ limit: '100kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '100kb' }));

// --- FILE UPLOAD & STATIC SERVING ---
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) { fs.mkdirSync(uploadDir); }
app.use('/uploads', express.static(uploadDir));

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype === "image/png" && file.originalname.match(/\.(png)$/i)) {
            cb(null, true);
        } else {
            cb(new Error("Only .png files are allowed!"), false);
        }
    }
});

// --- MYSQL DATABASE SETUP ---
const dbPool = mysql.createPool({
    host: process.env.MYSQLHOST, user: process.env.MYSQLUSER, password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE, port: process.env.MYSQLPORT || 3306,
    waitForConnections: true, connectionLimit: 10, queueLimit: 0
});

// --- DATABASE INITIALIZATION ---
async function initializeDatabase() {
    try {
        const connection = await dbPool.getConnection();
        console.log("Successfully connected to MySQL database.");
        await connection.query(`CREATE TABLE IF NOT EXISTS adminusers (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, role ENUM('admin','seller','buyer') NOT NULL DEFAULT 'buyer', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS tickets (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, status ENUM('awaiting', 'processing', 'completed') DEFAULT 'awaiting', license_key VARCHAR(255), payment_method VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES adminusers(id) ON DELETE CASCADE);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS ticket_messages (id INT AUTO_INCREMENT PRIMARY KEY, ticket_id INT NOT NULL, sender ENUM('user', 'seller') NOT NULL, message TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE);`);
        connection.release();
        console.log("Database schema verified.");
    } catch (error) {
        console.error("!!! DATABASE INITIALIZATION FAILED !!!", error);
        process.exit(1);
    }
}

// --- MIDDLEWARE ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized: No token provided.' });
    }
    if (!process.env.JWT_SECRET) {
        console.error("CRITICAL: JWT_SECRET environment variable is not set on the server.");
        return res.status(500).json({ message: "Server configuration error." });
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                console.log('Token validation failed: Token has expired.');
                return res.status(403).json({ message: 'Forbidden: Session has expired.' });
            }
            console.error('Token validation error:', err.message);
            return res.status(403).json({ message: 'Forbidden: Invalid session token.' });
        }
        req.user = user;
        next();
    });
};

// ===== THIS FUNCTION IS UPDATED WITH BETTER LOGGING =====
const verifyTurnstile = async (req, res, next) => {
    const secretKey = process.env.CLOUDFLARE_TURNSTILE_SECRET_KEY;
    if (!secretKey) {
        console.error("CRITICAL: CLOUDFLARE_TURNSTILE_SECRET_KEY is not set. Skipping CAPTCHA verification.");
        return next();
    }
    const token = req.body.turnstileToken;
    if (!token) {
        return res.status(400).json({ message: 'CAPTCHA token is required.' });
    }
    try {
        const formData = new URLSearchParams();
        formData.append('secret', secretKey);
        formData.append('response', token);
        if (req.ip) { formData.append('remoteip', req.ip); }
        
        const response = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', formData);
        
        const outcome = response.data;
        if (outcome.success) {
            next(); // Verification successful
        } else {
            // NEW: Log the specific error codes from Cloudflare for debugging
            console.error('Turnstile verification failed. Cloudflare error codes:', outcome['error-codes']);
            res.status(403).json({ message: 'Failed CAPTCHA verification.' });
        }
    } catch (error) {
        console.error('Server error during Turnstile verification:', error.message);
        res.status(500).json({ message: 'Error verifying CAPTCHA.' });
    }
};

const requireRole = (roles) => (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
        return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
    }
    next();
};

const requireAdmin = requireRole(['admin']);
const requireSeller = requireRole(['seller', 'admin']);
const requireBuyer = requireRole(['buyer']);
const requireAnyRole = requireRole(['admin', 'seller', 'buyer']);

const validateTicketCreation = [body('paymentMethod').trim().notEmpty().isIn(['PayPal', 'Crypto', 'Credit Card', 'Bank Transfer', 'Google Pay', 'Apple Pay', 'CashApp', 'Gag Pets', 'Secret Brainrots'])];
const validateTicketMessage = [body('message').trim().notEmpty().isLength({ min: 1, max: 1000 }).escape()];

// =================================================================
// --- API ROUTES ---
// =================================================================
const apiRouter = express.Router();

// --- AUTH/USER ROUTES ---
apiRouter.post('/login', verifyTurnstile, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Invalid request.' });
    try {
        const [rows] = await dbPool.query("SELECT * FROM adminusers WHERE username = ?", [username]);
        if (rows.length === 0) return res.status(401).json({ message: 'Invalid credentials' });
        const user = rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });
        const payload = { id: user.id, username: user.username, role: user.role };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '8h' });
        res.json({ success: true, token, username: user.username, role: user.role });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

apiRouter.post('/register', verifyTurnstile, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || username.length < 3) {
        return res.status(400).json({ message: 'Invalid username or password.' });
    }
    try {
        const [existing] = await dbPool.query("SELECT id FROM adminusers WHERE username = ?", [username]);
        if (existing.length > 0) {
            return res.status(409).json({ message: 'Username already taken.' });
        }
        const hashedPassword = await bcrypt.hash(password, 12);
        await dbPool.query("INSERT INTO adminusers (username, password_hash, role) VALUES (?, ?, 'buyer')", [username, hashedPassword]);
        res.status(201).json({ success: true, message: 'User created.' });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

// --- TICKET ROUTES ---
apiRouter.post('/tickets', verifyTurnstile, verifyToken, requireBuyer, validateTicketCreation, async (req, res) => {
    const { paymentMethod } = req.body;
    try {
        const [existing] = await dbPool.query("SELECT id FROM tickets WHERE user_id = ? AND status != 'completed'", [req.user.id]);
        if (existing.length > 0) return res.status(400).json({ message: 'You already have an open ticket.' });
        const [result] = await dbPool.query("INSERT INTO tickets (user_id, payment_method) VALUES (?, ?)", [req.user.id, paymentMethod]);
        const ticketId = result.insertId;
        await dbPool.query("INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, 'seller', ?)", [ticketId, `Welcome! A seller will be with you shortly to help you purchase with ${paymentMethod}.`]);
        const [tickets] = await dbPool.query(`SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`, [ticketId]);
        const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [ticketId]);
        tickets[0].messages = messages;
        res.status(201).json(tickets[0]);
    } catch (error) {
        res.status(500).json({ message: 'Failed to create ticket' });
    }
});

apiRouter.get('/tickets/my', verifyToken, requireBuyer, async (req, res) => {
    try {
        const [tickets] = await dbPool.query(`SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.user_id = ? ORDER BY t.updated_at DESC`, [req.user.id]);
        for (let ticket of tickets) {
            const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [ticket.id]);
            ticket.messages = messages;
        }
        res.json(tickets);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch tickets' });
    }
});

apiRouter.get('/tickets/all', verifyToken, requireSeller, async (req, res) => {
    try {
        const [tickets] = await dbPool.query(`SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id ORDER BY t.updated_at DESC`);
        for (let ticket of tickets) {
            const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [ticket.id]);
            ticket.messages = messages;
        }
        res.json(tickets);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch all tickets' });
    }
});

apiRouter.post('/tickets/:id/messages', verifyToken, requireAnyRole, validateTicketMessage, async (req, res) => {
    const { id } = req.params;
    const { message } = req.body;
    try {
        const [tickets] = await dbPool.query("SELECT * FROM tickets WHERE id = ?", [id]);
        if (tickets.length === 0) return res.status(404).json({ message: 'Ticket not found.' });
        const ticket = tickets[0];
        const senderType = (req.user.role === 'buyer') ? 'user' : 'seller';
        if (senderType === 'user' && ticket.user_id !== req.user.id) {
             return res.status(403).json({ message: 'Forbidden' });
        }
        await dbPool.query("INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, ?, ?)", [id, senderType, message]);
        if (ticket.status === 'awaiting') {
            await dbPool.query("UPDATE tickets SET status = 'processing', updated_at = CURRENT_TIMESTAMP WHERE id = ?", [id]);
        } else {
            await dbPool.query("UPDATE tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", [id]);
        }
        const [updatedTickets] = await dbPool.query(`SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`, [id]);
        const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [id]);
        updatedTickets[0].messages = messages;
        res.json(updatedTickets[0]);
    } catch (error) {
        res.status(500).json({ message: 'Failed to add message' });
    }
});

apiRouter.post('/tickets/:id/complete', verifyToken, requireSeller, async (req, res) => {
    const { id } = req.params;
    const { licenseKey } = req.body;
    if (!licenseKey || licenseKey.trim() === '') {
        return res.status(400).json({ message: 'License key is required to complete a ticket.' });
    }
    try {
        const [tickets] = await dbPool.query("SELECT * FROM tickets WHERE id = ?", [id]);
        if (tickets.length === 0) return res.status(404).json({ message: 'Ticket not found.' });
        await dbPool.query(
            "UPDATE tickets SET status = 'completed', license_key = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", 
            [licenseKey.trim(), id]
        );
        await dbPool.query("INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, 'seller', ?)", [id, `Your purchase is complete! Your license key is: ${licenseKey.trim()}`]);
        const [updatedTickets] = await dbPool.query(`SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`, [id]);
        const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [id]);
        updatedTickets[0].messages = messages;
        res.json(updatedTickets[0]);
    } catch (error) {
        console.error('Error completing ticket:', error);
        res.status(500).json({ message: 'Failed to complete ticket' });
    }
});

apiRouter.delete('/tickets/:id', verifyToken, requireSeller, async (req, res) => {
    const { id } = req.params;
    try {
        await dbPool.query("DELETE FROM ticket_messages WHERE ticket_id = ?", [id]);
        await dbPool.query("DELETE FROM tickets WHERE id = ?", [id]);
        res.json({ success: true, message: `Ticket #${id} has been permanently deleted.` });
    } catch (error) {
        console.error('Error deleting ticket:', error);
        res.status(500).json({ message: 'Failed to delete ticket' });
    }
});

// --- OTHER ADMIN ROUTES ---
apiRouter.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));
apiRouter.get('/clients', verifyToken, requireSeller, (req, res) => res.json({ count: clients.size, clients: Array.from(clients.values()) }));

app.use('/api', apiRouter);


// --- FRONTEND ROUTE HANDLER ---
app.get('/seller', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'seller.html'));
});
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- GLOBAL ERROR HANDLING MIDDLEWARE ---
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// --- START SERVER ---
async function startServer() {
    await initializeDatabase();
    app.listen(PORT, () => console.log(`Eps1llon Hub Server running on port ${PORT}`));
}

startServer();
