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

// --- Session Middleware ---
app.use(session({
    store: new pgSession({
        pool: pool,
        tableName: 'user_sessions'
    }),
    secret: process.env.SESSION_SECRET || 'your-super-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }
}));

// --- Create Tables ---
const createTables = async () => {
    const userTableQuery = `CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, full_name VARCHAR(200), email VARCHAR(100) UNIQUE, password_hash VARCHAR(255), created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`;
    const sessionTableQuery = `CREATE TABLE IF NOT EXISTS "user_sessions" ("sid" varchar NOT NULL COLLATE "default", "sess" json NOT NULL, "expire" timestamp(6) NOT NULL) WITH (OIDS=FALSE); ALTER TABLE "user_sessions" ADD CONSTRAINT "session_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE; CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "user_sessions" ("expire");`;
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
        const query = 'INSERT INTO users(full_name, email, password_hash) VALUES($1, $2, $3) RETURNING *';
        await pool.query(query, [fullName, email, passwordHash]);
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
            req.session.user = { id: user.id, name: user.full_name, email: user.email };
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

// --- NEW: Gemini API Endpoint ---
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
