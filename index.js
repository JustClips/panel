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
            "img-src": ["'self'", "data:", "https://i.imgur.com", "https://cdn.discordapp.com"],
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
            // THIS LINE IS NOW FIXED
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

// --- MYSQL DATABASE SETUP ---
const dbPool = mysql.createPool({
    host: process.env.MYSQLHOST, user: process.env.MYSQLUSER, password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE, port: process.env.MYSQLPORT || 3306,
    waitForConnections: true, connectionLimit: 10, queueLimit: 0
});

// --- DATABASE INITIALIZATION & AUTOMATIC REPAIR ---
async function initializeDatabase() {
    let connection;
    try {
        connection = await dbPool.getConnection();
        console.log("Successfully connected to MySQL database.");

        await connection.query(`CREATE TABLE IF NOT EXISTS adminusers (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255), role ENUM('admin','seller','buyer') NOT NULL DEFAULT 'buyer', discord_id VARCHAR(255) UNIQUE NULL, discord_avatar VARCHAR(255) NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS tickets (id INT AUTO_INCREMENT PRIMARY KEY, user_id INT NOT NULL, status ENUM('awaiting', 'processing', 'completed') DEFAULT 'awaiting', license_key VARCHAR(255), payment_method VARCHAR(50), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES adminusers(id) ON DELETE CASCADE);`);
        await connection.query(`CREATE TABLE IF NOT EXISTS ticket_messages (id INT AUTO_INCREMENT PRIMARY KEY, ticket_id INT NOT NULL, sender ENUM('user', 'seller') NOT NULL, message TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE);`);

        const [discordColumns] = await connection.query(`SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'adminusers' AND COLUMN_NAME = 'discord_id'`, [process.env.MYSQLDATABASE]);
        if (discordColumns.length === 0) {
            console.log("SCHEMA-FIX: Adding 'discord_id' and 'discord_avatar' columns to 'adminusers' table...");
            await connection.query(`ALTER TABLE adminusers ADD COLUMN discord_id VARCHAR(255) UNIQUE NULL, ADD COLUMN discord_avatar VARCHAR(255) NULL`);
            console.log("SCHEMA-FIX: Columns added successfully.");
        }
        const [passwordColumnInfo] = await connection.query(`SELECT IS_NULLABLE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'adminusers' AND COLUMN_NAME = 'password_hash'`, [process.env.MYSQLDATABASE]);
        if (passwordColumnInfo.length > 0 && passwordColumnInfo[0].IS_NULLABLE === 'NO') {
            console.log("SCHEMA-FIX: 'password_hash' column has incorrect NOT NULL rule. Fixing...");
            await connection.query(`ALTER TABLE adminusers MODIFY COLUMN password_hash VARCHAR(255) NULL`);
            console.log("SCHEMA-FIX: 'password_hash' column rule fixed successfully.");
        }
        const [claimedByColumn] = await connection.query(`SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'tickets' AND COLUMN_NAME = 'claimed_by'`, [process.env.MYSQLDATABASE]);
        if (claimedByColumn.length === 0) {
            console.log("SCHEMA-FIX: Adding 'claimed_by' column and foreign key to 'tickets' table...");
            await connection.query(
                `ALTER TABLE tickets 
                    ADD COLUMN claimed_by INT NULL DEFAULT NULL, 
                    ADD CONSTRAINT fk_claimed_by FOREIGN KEY (claimed_by) REFERENCES adminusers(id) ON DELETE SET NULL`
            );
            console.log("SCHEMA-FIX: 'tickets' table updated successfully.");
        }

        console.log("Database schema verified and up-to-date.");
    } catch (error) {
        console.error("!!! DATABASE INITIALIZATION FAILED !!!", error);
        process.exit(1);
    } finally {
        if (connection) connection.release();
    }
}


// --- MIDDLEWARE ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Forbidden: Invalid Token' });
        req.user = user;
        next();
    });
};

const verifyTurnstile = async (req, res, next) => {
    const secretKey = process.env.CLOUDFLARE_TURNSTILE_SECRET_KEY;
    if (!secretKey) return next();
    const token = req.body.turnstileToken;
    if (!token) return res.status(400).json({ message: 'CAPTCHA token is required.' });
    try {
        const formData = new URLSearchParams();
        formData.append('secret', secretKey);
        formData.append('response', token);
        if (req.ip) { formData.append('remoteip', req.ip); }
        const response = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', formData);
        if (response.data.success) {
            next();
        } else {
            console.error('Turnstile verification failed. Cloudflare error codes:', response.data['error-codes']);
            res.status(403).json({ message: 'Failed CAPTCHA verification.' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Error verifying CAPTCHA.' });
    }
};

const requireRole = (roles) => (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
        return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
    }
    next();
};
const requireSeller = requireRole(['seller', 'admin']);
const requireBuyer = requireRole(['buyer']);
const requireAnyRole = requireRole(['admin', 'seller', 'buyer']);

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
        if (!user.password_hash) {
            return res.status(401).json({ message: 'Invalid credentials. Please log in with Discord.' });
        }
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
    if (!username || !password || username.length < 3) return res.status(400).json({ message: 'Invalid username or password.' });
    try {
        const [existing] = await dbPool.query("SELECT id FROM adminusers WHERE username = ?", [username]);
        if (existing.length > 0) return res.status(409).json({ message: 'Username already taken.' });
        const hashedPassword = await bcrypt.hash(password, 12);
        const [result] = await dbPool.query("INSERT INTO adminusers (username, password_hash, role) VALUES (?, ?, 'buyer')", [username, hashedPassword]);
        const newUserId = result.insertId;
        const payload = { id: newUserId, username: username, role: 'buyer' };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '8h' });
        res.status(201).json({
            success: true,
            message: 'User created successfully.',
            token: token,
            username: username,
            role: 'buyer'
        });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});
apiRouter.get('/auth/discord', (req, res) => {
    const discordAuthUrl = 'https://discord.com/api/oauth2/authorize';
    const params = new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        redirect_uri: 'https://eps1llon.win/api/auth/discord/callback',
        response_type: 'code',
        scope: 'identify email'
    });
    res.redirect(`${discordAuthUrl}?${params.toString()}`);
});
apiRouter.get('/auth/discord/callback', async (req, res) => {
    const code = req.query.code;
    if (!code) return res.status(400).send('Error: Missing Discord authorization code.');
    try {
        const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
            client_id: process.env.DISCORD_CLIENT_ID,
            client_secret: process.env.DISCORD_CLIENT_SECRET,
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: 'https://eps1llon.win/api/auth/discord/callback'
        }), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });
        const accessToken = tokenResponse.data.access_token;
        const userResponse = await axios.get('https://discord.com/api/users/@me', {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        const { id: discordId, username, avatar } = userResponse.data;
        let [users] = await dbPool.query("SELECT * FROM adminusers WHERE discord_id = ?", [discordId]);
        let user = users[0];
        if (!user) {
            const [result] = await dbPool.query(
                "INSERT INTO adminusers (username, password_hash, role, discord_id, discord_avatar) VALUES (?, NULL, 'buyer', ?, ?)",
                [username, discordId, avatar]
            );
            user = { id: result.insertId, username, role: 'buyer' };
        }
        const payload = { id: user.id, username: user.username, role: user.role };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '8h' });
        res.redirect(`/#token=${token}`);
    } catch (error) {
        console.error("Discord OAuth Error:", error.response ? error.response.data : error.message);
        res.status(500).send('An error occurred during Discord authentication.');
    }
});

// =================================================================
// --- NEW SERVER VERIFICATION ROUTES START HERE ---
// =================================================================

// This route starts the verification process. Your website button should link here.
apiRouter.get('/discord/verify-auth', (req, res) => {
    const params = new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        redirect_uri: 'https://eps1llon.win/api/discord/verify-callback',
        response_type: 'code',
        scope: 'identify guilds.join' // Scopes needed to verify and add users
    });
    res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

// This route handles the logic after the user authorizes on Discord.
apiRouter.get('/discord/verify-callback', async (req, res) => {
    const code = req.query.code;
    if (!code) {
        return res.status(400).send('Authorization failed: No authorization code was provided by Discord.');
    }

    try {
        // Step 1: Exchange the authorization code for an access token
        const tokenResponse = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
            client_id: process.env.DISCORD_CLIENT_ID,
            client_secret: process.env.DISCORD_CLIENT_SECRET,
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: 'https://eps1llon.win/api/discord/verify-callback'
        }), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        const { access_token } = tokenResponse.data;

        // Step 2: Get the user's Discord profile information
        const userResponse = await axios.get('https://discord.com/api/users/@me', {
            headers: { 'Authorization': `Bearer ${access_token}` }
        });
        const discordUser = userResponse.data;

        // Step 3: Add the user to your Discord server using their access token
        await axios.put(
            `https://discord.com/api/v10/guilds/${process.env.DISCORD_GUILD_ID}/members/${discordUser.id}`,
            { access_token: access_token },
            { headers: { 'Authorization': `Bot ${process.env.DISCORD_BOT_TOKEN}` } }
        );

        // Step 4: Add the "Verified" role to the user
        await axios.put(
            `https://discord.com/api/v10/guilds/${process.env.DISCORD_GUILD_ID}/members/${discordUser.id}/roles/${process.env.DISCORD_VERIFIED_ROLE_ID}`,
            {}, // The body is empty for this request
            { headers: { 'Authorization': `Bot ${process.env.DISCORD_BOT_TOKEN}` } }
        );
        
        // Step 5: Send a success message or redirect to a success page
        res.send(`<h1>✅ Verification Complete!</h1><p>Welcome, ${discordUser.username}! You now have access to the server. You can close this window.</p>`);

    } catch (error) {
        console.error("Verification Callback Error:", error.response ? error.response.data : error.message);
        res.status(500).send('An error occurred during verification. This could be due to missing permissions for the bot.');
    }
});

// =================================================================
// --- NEW SERVER VERIFICATION ROUTES END HERE ---
// =================================================================


// --- TICKET ROUTES ---
apiRouter.get('/tickets/all', verifyToken, requireSeller, async (req, res) => {
    try {
        const query = `
            SELECT
                t.*,
                buyer.username as buyer_name,
                seller.username as claimed_by_name,
                (SELECT sender FROM ticket_messages tm WHERE tm.ticket_id = t.id ORDER BY tm.created_at DESC LIMIT 1) as last_message_sender
            FROM tickets t
            JOIN adminusers buyer ON t.user_id = buyer.id
            LEFT JOIN adminusers seller ON t.claimed_by = seller.id
            ORDER BY t.updated_at DESC
        `;
        const [tickets] = await dbPool.query(query);
        for (let ticket of tickets) {
            const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [ticket.id]);
            ticket.messages = messages;
        }
        res.json(tickets);
    } catch (error) {
        console.error("Error fetching all tickets:", error);
        res.status(500).json({ message: 'Failed to fetch all tickets' });
    }
});
apiRouter.post('/tickets/:id/claim', verifyToken, requireSeller, async (req, res) => {
    const { id } = req.params;
    const sellerId = req.user.id;
    try {
        const [tickets] = await dbPool.query("SELECT * FROM tickets WHERE id = ? FOR UPDATE", [id]);
        if (tickets.length === 0) return res.status(404).json({ message: 'Ticket not found.' });
        if (tickets[0].claimed_by) return res.status(409).json({ message: 'Ticket has already been claimed.' });
        await dbPool.query("UPDATE tickets SET claimed_by = ?, status = 'processing', updated_at = CURRENT_TIMESTAMP WHERE id = ?", [sellerId, id]);
        const sellerUsername = req.user.username;
        await dbPool.query("INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, 'seller', ?)", [id, `${sellerUsername} has joined the chat and will assist you.`]);
        res.json({ success: true, message: `You have claimed ticket #${id}` });
    } catch (error) {
        console.error('Error claiming ticket:', error);
        res.status(500).json({ message: 'Failed to claim ticket' });
    }
});
apiRouter.post('/tickets', verifyToken, requireBuyer, async (req, res) => {
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
            const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [ticket.id]); // Fixed a bug here
            ticket.messages = messages;
        }
        res.json(tickets);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch tickets' });
    }
});
apiRouter.post('/tickets/:id/messages', verifyToken, requireAnyRole, async (req, res) => {
    const { id } = req.params;
    const { message } = req.body;
    try {
        const [tickets] = await dbPool.query("SELECT * FROM tickets WHERE id = ?", [id]);
        if (tickets.length === 0) return res.status(404).json({ message: 'Ticket not found.' });
        const ticket = tickets[0];
        const senderType = (req.user.role === 'buyer') ? 'user' : 'seller';
        if (senderType === 'user' && ticket.user_id !== req.user.id) return res.status(403).json({ message: 'Forbidden' });
        if (senderType === 'seller' && req.user.role !== 'admin' && ticket.claimed_by && ticket.claimed_by !== req.user.id) {
            return res.status(403).json({ message: 'This ticket is claimed by another seller.' });
        }
        await dbPool.query("INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, ?, ?)", [id, senderType, message]);
        if (ticket.status === 'awaiting') {
            await dbPool.query("UPDATE tickets SET status = 'processing', updated_at = CURRENT_TIMESTAMP WHERE id = ?", [id]);
        } else {
            await dbPool.query("UPDATE tickets SET updated_at = CURRENT_TIMESTAMP WHERE id = ?", [id]);
        }
        const [updatedTickets] = await dbPool.query(`SELECT t.*, buyer.username as buyer_name, seller.username as claimed_by_name FROM tickets t JOIN adminusers buyer ON t.user_id = buyer.id LEFT JOIN adminusers seller ON t.claimed_by = seller.id WHERE t.id = ?`, [id]);
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
        return res.status(400).json({ message: 'License key is required.' });
    }
    try {
        await dbPool.query("UPDATE tickets SET status = 'completed', license_key = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", [licenseKey.trim(), id]);
        await dbPool.query("INSERT INTO ticket_messages (ticket_id, sender, message) VALUES (?, 'seller', ?)", [id, `Your purchase is complete! Your license key is: ${licenseKey.trim()}`]);
        const [updatedTickets] = await dbPool.query(`SELECT t.*, u.username as buyer_name FROM tickets t JOIN adminusers u ON t.user_id = u.id WHERE t.id = ?`, [id]);
        const [messages] = await dbPool.query("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY created_at ASC", [id]);
        updatedTickets[0].messages = messages;
        res.json(updatedTickets[0]);
    } catch (error) {
        res.status(500).json({ message: 'Failed to complete ticket' });
    }
});
apiRouter.delete('/tickets/:id', verifyToken, requireSeller, async (req, res) => {
    const { id } = req.params;
    try {
        await dbPool.query("DELETE FROM ticket_messages WHERE ticket_id = ?", [id]);
        await dbPool.query("DELETE FROM tickets WHERE id = ?", [id]);
        res.json({ success: true, message: `Ticket #${id} deleted.` });
    } catch (error) {
        res.status(500).json({ message: 'Failed to delete ticket' });
    }
});


apiRouter.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));
app.use('/api', apiRouter);

// --- FRONTEND ROUTE HANDLER ---
app.get('/seller', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'seller.html'));
});
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- GLOBAL ERROR HANDLING ---
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
