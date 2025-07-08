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
    const rateLimit = require('express-rate-limit');

    const app = express();
    const server = http.createServer(app);
    const io = new Server(server);

    const port = 3000;
    const saltRounds = 10;
    
    app.set('trust proxy', 1);

    // --- Brute Force Protection Middleware ---
    const loginLimiter = rateLimit({
        windowMs: 15 * 60 * 1000, 
        max: 5, // Start showing CAPTCHA after 5 requests
        message: { message: 'Too many login attempts. Please solve the CAPTCHA.' },
        handler: (req, res, next, options) => {
            // This handler is called when the rate limit is exceeded.
            // We'll tell the frontend to show the CAPTCHA.
            req.showCaptcha = true;
            next();
        },
        standardHeaders: true,
        legacyHeaders: false, 
    });

    // ... (rest of your existing server.js code up to the /login route) ...

    // --- Apply rate limiter to the login route ---
    app.post('/login', loginLimiter, async (req, res) => {
        const { email, password, captcha } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required.' });
        }

        // If CAPTCHA is shown, it must be correct
        if (req.showCaptcha) {
            if (!captcha || parseInt(captcha) !== req.session.captcha) {
                return res.status(400).json({ message: 'Invalid CAPTCHA answer.', showCaptcha: true });
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
                // Successful login, reset CAPTCHA state
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

    // --- NEW: Endpoint to get a CAPTCHA question ---
    app.get('/api/captcha', (req, res) => {
        const num1 = Math.floor(Math.random() * 10) + 1;
        const num2 = Math.floor(Math.random() * 10) + 1;
        req.session.captcha = num1 + num2; // Store the correct answer in the session
        res.json({ question: `What is ${num1} + ${num2}?` });
    });

    // ... (rest of your existing server.js code) ...
