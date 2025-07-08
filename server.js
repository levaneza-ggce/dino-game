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
    const rateLimit = require('express-rate-limit'); // For brute-force protection

    const app = express();
    const server = http.createServer(app);
    const io = new Server(server);

    const port = 3000;
    const saltRounds = 10;
    
    app.set('trust proxy', 1);

    // --- Brute Force Protection Middleware for Login ---
    const loginLimiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 5, // Limit each IP to 5 login requests per windowMs
        handler: (req, res, next, options) => {
            // This handler is called when the rate limit is exceeded.
            // We'll add a flag to the request to show the CAPTCHA on the frontend.
            req.showCaptcha = true;
            next();
        },
        standardHeaders: true,
        legacyHeaders: false,
    });


    // ... (All other middleware and setup code remains the same) ...
    // --- Session Middleware, Create Tables, etc. ---
    const isProduction = process.env.NODE_ENV === 'production';
    const sessionMiddleware = session({
        store: new pgSession({ pool: pool, tableName: 'user_sessions' }),
        secret: process.env.SESSION_SECRET || 'your-super-secret-key',
        resave: false, saveUninitialized: false, rolling: true,
        cookie: { maxAge: 15 * 60 * 1000, httpOnly: true, secure: isProduction, sameSite: 'strict' }
    });
    app.use(sessionMiddleware);
    io.engine.use(sessionMiddleware);
    app.use((req, res, next) => {
        if (req.session.user && (req.session.ip !== req.ip || req.session.userAgent !== req.headers['user-agent'])) {
            req.session.destroy(); res.clearCookie('connect.sid'); return res.status(401).json({ message: 'Invalid session.' });
        }
        next();
    });
    const createTables = async () => {
        const userTableQuery = `CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, full_name VARCHAR(200), email VARCHAR(100) UNIQUE, password_hash VARCHAR(255), created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, profile_picture_url VARCHAR(255) DEFAULT '/default-pfp.png');`;
        const sessionTableQuery = `CREATE TABLE IF NOT EXISTS "user_sessions" ("sid" varchar NOT NULL COLLATE "default", "sess" json NOT NULL, "expire" timestamp(6) NOT NULL, CONSTRAINT "session_pkey" PRIMARY KEY ("sid")); CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "user_sessions" ("expire");`;
        try { await pool.query(userTableQuery); await pool.query(sessionTableQuery); } catch (err) { console.error('Error creating tables', err.stack); }
    };
    createTables();
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: true }));
    app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


    // --- API Endpoints ---
    // ... (Your /register, /logout, /api/profile, etc. endpoints remain the same) ...
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

    // --- Apply rate limiter to the login route ---
    app.post('/login', loginLimiter, async (req, res) => {
        const { email, password, captcha } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required.' });
        }

        // If CAPTCHA is required, validate it
        if (req.showCaptcha) {
            if (!captcha || parseInt(captcha) !== req.session.captcha) {
                return res.status(401).json({ message: 'Invalid CAPTCHA answer.', showCaptcha: true });
            }
        }

        try {
            const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
            if (rows.length === 0) {
                return res.status(401).json({ message: 'Invalid credentials.', showCaptcha: req.showCaptcha });
            }

            const user = rows[0];
            const isMatch = await bcrypt.compare(password, user.password_hash);

            if (isMatch) {
                req.session.captcha = null; // Clear captcha on successful login
                req.session.user = { id: user.id, name: user.full_name, email: user.email, joined: user.created_at, pfp: user.profile_picture_url };
                req.session.ip = req.ip; 
                req.session.userAgent = req.headers['user-agent'];
                res.status(200).json({ message: `Welcome back, ${user.full_name}!` });
            } else {
                res.status(401).json({ message: 'Invalid credentials.', showCaptcha: req.showCaptcha });
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

    // --- NEW: Endpoint to get a CAPTCHA question ---
    app.get('/api/captcha', (req, res) => {
        const num1 = Math.floor(Math.random() * 10) + 1;
        const num2 = Math.floor(Math.random() * 10) + 1;
        req.session.captcha = num1 + num2; // Store the correct answer in the session
        res.json({ question: `What is ${num1} + ${num2}?` });
    });

    // ... (rest of your server.js code) ...

    // --- Static File Middleware (LAST) ---
    app.use(express.static(path.join(__dirname)));
    
    // --- 404 Catch-all Route ---
    app.use((req, res, next) => {
        res.status(404).sendFile(path.join(__dirname, '404.html'));
    });

    // --- Start the Server ---
    server.listen(port, () => {
        console.log(`Arcade server listening on port ${port}`);
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
