    require('dotenv').config(); 
    const express = require('express');
    const bodyParser = require('body-parser');
    const { Pool } = require('pg');
    const path = require('path');
    const bcrypt = require('bcrypt');
    const session = require('express-session');
    const pgSession = require('connect-pg-simple')(session);

    const app = express();
    const port = 3000;
    const saltRounds = 10;

    // --- Database Connection ---
    const pool = new Pool({
        user: process.env.DB_USER,
        host: process.env.DB_HOST,
        database: process.env.DB_DATABASE,
        password: process.env.DB_PASSWORD,
        port: process.env.DB_PORT,
    });
    
    // --- Session Middleware with Enhanced Security ---
    const isProduction = process.env.NODE_ENV === 'production';
    app.set('trust proxy', 1); // Trust first proxy, needed for secure cookies if behind Nginx

    app.use(session({
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
    }));

    // --- NEW: Session Hijacking Prevention Middleware ---
    app.use((req, res, next) => {
        if (req.session.user) {
            // Check if the IP and User-Agent match what's stored in the session
            if (req.session.ip !== req.ip || req.session.userAgent !== req.headers['user-agent']) {
                // If they don't match, destroy the session and log the user out
                console.warn(`Potential session hijacking attempt for user ${req.session.user.email}.`);
                req.session.destroy();
                res.clearCookie('connect.sid');
                return res.status(401).json({ message: 'Invalid session.' });
            }
        }
        next();
    });


    // --- Create Database Tables ---
    const createTables = async () => {
        const userTableQuery = `CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, full_name VARCHAR(200), email VARCHAR(100) UNIQUE, password_hash VARCHAR(255), created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`;
        const sessionTableQuery = `
            CREATE TABLE IF NOT EXISTS "user_sessions" (
              "sid" varchar NOT NULL COLLATE "default",
              "sess" json NOT NULL,
              "expire" timestamp(6) NOT NULL,
              CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
            );
            CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "user_sessions" ("expire");
        `;
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

    // --- API Endpoints ---
    app.post('/register', async (req, res) => {
        const { fullName, email, password } = req.body;
        if (!fullName || !email || !password) return res.status(400).json({ message: 'All fields are required.' });
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
                // *** BIND SESSION ON LOGIN ***
                req.session.user = { id: user.id, name: user.full_name, email: user.email, joined: user.created_at };
                req.session.ip = req.ip; // Store IP address
                req.session.userAgent = req.headers['user-agent']; // Store User-Agent
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
        res.json({ user: req.session.user });
    });
    
    app.post('/api/change-password', async (req, res) => {
        if (!req.session.user) {
            return res.status(401).json({ message: 'Not authenticated.' });
        }

        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ message: 'All password fields are required.' });
        }

        try {
            const userId = req.session.user.id;
            const { rows } = await pool.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
            const user = rows[0];

            const isMatch = await bcrypt.compare(currentPassword, user.password_hash);
            if (!isMatch) {
                return res.status(401).json({ message: 'Incorrect current password.' });
            }

            const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);
            await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newPasswordHash, userId]);

            res.status(200).json({ message: 'Password updated successfully!' });

        } catch (err) {
            console.error('Password change error:', err);
            res.status(500).json({ message: 'An error occurred while changing password.' });
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
            console.error('Error in /api/generate-idea:', error);
            res.status(500).json({ message: 'Failed to generate idea.' });
        }
    });

    // --- Static File Middleware (LAST) ---
    app.use(express.static(path.join(__dirname)));

    app.listen(port, () => console.log(`Arcade backend listening on port ${port}`));
