    require('dotenv').config(); 
    const express = require('express');
    const http = require('http'); // Required for Socket.IO
    const { Server } = require("socket.io"); // Required for Socket.IO
    const bodyParser = require('body-parser');
    const { Pool } = require('pg');
    const path = require('path');
    const bcrypt = require('bcrypt');
    const session = require('express-session');
    const pgSession = require('connect-pg-simple')(session);
    const multer = require('multer');
    const fs = require('fs');

    const app = express();
    const server = http.createServer(app); // Create an HTTP server from the Express app
    const io = new Server(server); // Attach Socket.IO to the server

    const port = 3000;
    const saltRounds = 10;
    
    app.set('trust proxy', 1);

    // --- File Upload Setup ---
    const uploadDir = 'uploads';
    if (!fs.existsSync(uploadDir)){ fs.mkdirSync(uploadDir); }
    const storage = multer.diskStorage({
        destination: (req, file, cb) => cb(null, uploadDir + '/'),
        filename: (req, file, cb) => {
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
    io.engine.use(sessionMiddleware); // Share session with Socket.IO

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

    // --- API Endpoints ---
    // (All your existing API endpoints like /register, /login, etc. go here)
    // ...

    // --- NEW: Socket.IO Chat Logic ---
    io.on('connection', (socket) => {
        const session = socket.request.session;
        if (!session.user) {
            console.log('A guest tried to connect to chat.');
            socket.disconnect();
            return;
        }
        
        console.log(`${session.user.name} connected to chat.`);

        // Broadcast a 'user connected' message
        socket.broadcast.emit('chat message', {
            user: 'System',
            text: `${session.user.name} has joined the chat.`
        });

        socket.on('chat message', (msg) => {
            // Broadcast the message to everyone, including the sender
            io.emit('chat message', {
                user: session.user.name,
                text: msg
            });
        });

        socket.on('disconnect', () => {
            console.log(`${session.user.name} disconnected from chat.`);
            // Broadcast a 'user disconnected' message
            io.emit('chat message', {
                user: 'System',
                text: `${session.user.name} has left the chat.`
            });
        });
    });


    // --- Static File Middleware (LAST) ---
    app.use(express.static(path.join(__dirname)));

    // --- Start the Server ---
    server.listen(port, () => {
        console.log(`Arcade server listening on port ${port}`);
    });
