    require('dotenv').config(); 
    const express = require('express');
    const http = require('http');
    const { Server } = require("socket.io");
    const bodyParser = require('body-parser');
    const { Pool } = require('pg');
    const path = require('path');
    const bcrypt = require('bcrypt');
    const session = require('express-session');
    const pgSession = require('connect-pg-simple')(session);
    const multer = require('multer');
    const fs = require('fs');

    const app = express();
    const server = http.createServer(app);
    const io = new Server(server);

    const port = 3000;
    const saltRounds = 10;
    
    app.set('trust proxy', 1);

    // --- File Upload Setup ---
    const uploadDir = 'uploads';
    if (!fs.existsSync(uploadDir)){ fs.mkdirSync(uploadDir); }
    const storage = multer.diskStorage({
        destination: (req, file, cb) => cb(null, uploadDir + '/'),
        filename: (req, file, cb) => {
            if (!req.session || !req.session.user) {
                return cb(new Error('User not authenticated for upload'));
            }
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            cb(null, req.session.user.id + '-' + uniqueSuffix + path.extname(file.originalname));
        }
    });
    const upload = multer({ storage: storage });

    // --- Database Connection ---
    const pool = new Pool({
        user: process.env.DB_USER,
        host: process.env.DB_HOST,
        database: process.env.DB_DATABASE,
        password: process.env.DB_PASSWORD,
        port: process.env.DB_PORT,
    });
    
    // --- Session Middleware ---
    const isProduction = process.env.NODE_ENV === 'production';
    const sessionMiddleware = session({
        store: new pgSession({
            pool: pool,
            tableName: 'user_sessions'
        }),
        secret: process.env.SESSION_SECRET || 'your-super-secret-key',
        resave: false,
        saveUninitialized: false,
        rolling: true,
        cookie: { 
            maxAge: 15 * 60 * 1000,
            httpOnly: true,
            secure: isProduction,
            sameSite: 'strict'
        }
    });
    app.use(sessionMiddleware);
    io.engine.use(sessionMiddleware);

    // --- Session Hijacking Prevention Middleware ---
    app.use((req, res, next) => {
        if (req.session.user && (req.session.ip !== req.ip || req.session.userAgent !== req.headers['user-agent'])) {
            req.session.destroy();
            res.clearCookie('connect.sid');
            return res.status(401).json({ message: 'Invalid session.' });
        }
        next();
    });

    // --- Create Tables ---
    const createTables = async () => {
        const userTableQuery = `CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, full_name VARCHAR(200), email VARCHAR(100) UNIQUE, password_hash VARCHAR(255), created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, profile_picture_url VARCHAR(255) DEFAULT '/default-pfp.png');`;
        const sessionTableQuery = `CREATE TABLE IF NOT EXISTS "user_sessions" ("sid" varchar NOT NULL COLLATE "default", "sess" json NOT NULL, "expire" timestamp(6) NOT NULL, CONSTRAINT "session_pkey" PRIMARY KEY ("sid")); CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "user_sessions" ("expire");`;
        try {
            await pool.query(userTableQuery);
            console.log('"users" table is ready.');
            await pool.query(sessionTableQuery);
            console.log('"user_sessions" table is ready.');
        } catch (err) {
            console.error('Error creating tables', err.stack);
        }
    };
    createTables();


    // --- Middleware ---
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: true }));
    app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

    // --- API Endpoints (Defined BEFORE static files) ---
    app.post('/register', async (req, res) => {
        const { fullName, email, password } = req.body;
        if (!fullName || !email || !password) return res.status(400).json({ message: 'All fields are required.' });
        const passwordValidation = validatePassword(password);
        if (!passwordValidation.isValid) return res.status(400).json({ message: passwordValidation.message });
        try {
            const passwordHash = await bcrypt.hash(password, saltRounds);
            await pool.query('INSERT INTO users(full_name, email, password_hash) VALUES($1, $2, $3)', [fullName, email, passwordHash]);
            res.status(201).json({ message: 'Registration successful!' });
        } catch (err) {
            res.status(err.code === '23505' ? 409 : 500).json({ message: err.code === '23505' ? 'Email already exists.' : 'An error occurred.' });
        }
    });

    app.post('/login', async (req, res) => {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: 'Email and password are required.' });
        try {
            const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
            if (rows.length === 0) return res.status(401).json({ message: 'Invalid credentials.' });
            const user = rows[0];
            const isMatch = await bcrypt.compare(password, user.password_hash);
            if (isMatch) {
                req.session.user = { id: user.id, name: user.full_name, email: user.email, joined: user.created_at, pfp: user.profile_picture_url };
                req.session.ip = req.ip; 
                req.session.userAgent = req.headers['user-agent'];
                res.status(200).json({ message: `Welcome back, ${user.full_name}!` });
            } else {
                res.status(401).json({ message: 'Invalid credentials.' });
            }
        } catch (err) {
            res.status(500).json({ message: 'An error occurred.' });
        }
    });

    app.get('/logout', (req, res) => {
        req.session.destroy(err => {
            if (err) return res.status(500).json({ message: 'Could not log out.' });
            res.clearCookie('connect.sid').status(200).json({ message: 'Logout successful.' });
        });
    });

    app.get('/api/session-status', (req, res) => {
        res.json({ loggedIn: !!req.session.user, user: req.session.user || null });
    });

    app.get('/api/profile', (req, res) => {
        if (!req.session.user) return res.status(401).json({ message: 'Not authenticated' });
        const profileData = { ...req.session.user, ip: req.session.ip };
        res.json({ user: profileData });
    });
    
    app.post('/api/change-password', async (req, res) => {
        if (!req.session.user) return res.status(401).json({ message: 'Not authenticated.' });
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) return res.status(400).json({ message: 'All password fields are required.' });
        const passwordValidation = validatePassword(newPassword);
        if (!passwordValidation.isValid) return res.status(400).json({ message: passwordValidation.message });
        try {
            const userId = req.session.user.id;
            const { rows } = await pool.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
            const user = rows[0];
            const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
            if (!isMatch) return res.status(401).json({ message: 'Incorrect current password.' });
            const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);
            await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newPasswordHash, userId]);
            res.status(200).json({ message: 'Password updated successfully!' });
        } catch (err) {
            res.status(500).json({ message: 'An error occurred.' });
        }
    });

    app.post('/api/upload-profile-picture', upload.single('pfp'), async (req, res) => {
        if (!req.session.user) return res.status(401).json({ message: 'Not authenticated.' });
        if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });
        try {
            const filePath = `/${uploadDir}/${req.file.filename}`;
            const userId = req.session.user.id;
            await pool.query('UPDATE users SET profile_picture_url = $1 WHERE id = $2', [filePath, userId]);
            req.session.user.pfp = filePath;
            res.status(200).json({ message: 'Profile picture updated!', filePath: filePath });
        } catch (error) {
            console.error('PFP upload error:', error);
            res.status(500).json({ message: 'Error updating profile picture.' });
        }
    });

    app.post('/api/generate-idea', async (req, res) => {
        const prompt = "Generate a creative concept for a new retro-style arcade game. Provide a catchy title, a one-sentence description, and a short list of core gameplay mechanics. Format the response as simple HTML with a <h3> for the title, a <p> for the description, and a <ul> with <li> items for the mechanics.";
        try {
            const chatHistory = [{ role: "user", parts: [{ text: prompt }] }];
            const payload = { contents: chatHistory };
            const apiKey = process.env.GEMINI_API_KEY || ""; 
            const apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
            const apiResponse = await fetch(apiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (!apiResponse.ok) throw new Error(`API request failed: ${apiResponse.statusText}`);
            const result = await apiResponse.json();
            const text = result.candidates?.[0]?.content?.parts?.[0]?.text;
            if (text) {
                res.status(200).json({ idea: text });
            } else {
                throw new Error("Invalid response structure from API.");
            }
        } catch (error) {
            res.status(500).json({ message: 'Failed to generate idea.' });
        }
    });

    // --- Socket.IO Chat Logic ---
    io.on('connection', (socket) => {
        const session = socket.request.session;
        if (!session.user) {
            console.log('A guest tried to connect to chat.');
            socket.disconnect();
            return;
        }
        
        console.log(`${session.user.name} connected to chat.`);

        socket.broadcast.emit('chat message', {
            user: 'System',
            text: `${session.user.name} has joined the chat.`
        });

        socket.on('chat message', (msg) => {
            io.emit('chat message', {
                user: session.user.name,
                text: msg
            });
        });

        socket.on('disconnect', () => {
            console.log(`${session.user.name} disconnected from chat.`);
            io.emit('chat message', {
                user: 'System',
                text: `${session.user.name} has left the chat.`
            });
        });
    });

    // --- Static File Middleware (LAST) ---
    app.use(express.static(path.join(__dirname)));

    // --- 404 Catch-all Route (Must be just before starting the server) ---
    app.use((req, res, next) => {
        res.status(404).sendFile(path.join(__dirname, '404.html'));
    });

    function validatePassword(password) {
        const hasUpperCase = /[A-Z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const isLongEnough = password.length >= 8;
        if (hasUpperCase && hasNumber && isLongEnough) return { isValid: true };
        const errors = [];
        if (!isLongEnough) errors.push("be at least 8 characters");
        if (!hasUpperCase) errors.push("contain an uppercase letter");
        if (!hasNumber) errors.push("contain a number");
        return { isValid: false, message: `Password must ${errors.join(', ')}.` };
    }

    // --- Start the Server ---
    server.listen(port, () => {
        console.log(`Arcade server listening on port ${port}`);
    });
