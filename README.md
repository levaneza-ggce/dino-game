# Levan's Arcade

Welcome to Levan's Arcade, a full-stack web application featuring a collection of retro-style games, a complete user authentication system, real-time chat, and more.

## Features

* **User Authentication:** Secure user registration and login system with password hashing (`bcrypt`) and session management.
* **User Profiles:** Users can view their profile, change their password, and upload a custom profile picture.
* **Security:** Implements session binding to IP address and User-Agent to prevent session hijacking, along with secure cookie flags (`httpOnly`, `secure`, `sameSite`).
* **Real-Time Chat:** A live chat room for logged-in users, built with WebSockets (`socket.io`).
* **Game Idea Generator:** A feature that uses the Gemini API to generate unique concepts for new retro games.
* **Custom 404 Page:** A styled "Not Found" page for a better user experience.
* **Reverse Proxy:** Uses Nginx to manage traffic and serve the application securely over HTTPS with a Let's Encrypt SSL certificate.

## The Games

* **Dino Game:** A classic side-scrolling runner.
* **Breakout:** An Atari-style brick-breaking game.
* **Starship Defender:** A space shooter where you fight off asteroids.
* **Flappy Bot:** A "Flappy Bird" style one-button game.
* **Pixel Doom:** A top-down, arena-style shooter.
* **Snake:** The classic game of growing your snake by eating food.
* **Vector Fury:** A vector-graphics shooter inspired by "Asteroids".
* **Pong:** The original arcade classic.

## Tech Stack

### Frontend
* HTML5
* CSS3
* Vanilla JavaScript

### Backend
* **Runtime:** Node.js
* **Framework:** Express.js
* **Database:** PostgreSQL
* **Web Server:** Nginx (as a reverse proxy)

### Key Libraries
* `pg`: PostgreSQL client for Node.js.
* `bcrypt`: For hashing passwords.
* `express-session` & `connect-pg-simple`: For managing user sessions stored in the database.
* `multer`: For handling file uploads (profile pictures).
* `socket.io`: For real-time chat functionality.
* `dotenv`: For managing environment variables.

## Setup and Installation

1.  **Prerequisites:**
    * Node.js (v20.x or later recommended)
    * PostgreSQL

2.  **Clone the Repository:**
    ```bash
    git clone <your_repository_url>
    cd <your_project_directory>
    ```

3.  **Install Dependencies:**
    ```bash
    npm install
    ```

4.  **Set Up the Database:**
    * Log in to PostgreSQL and create a new user and database.
        ```bash
        sudo -u postgres psql
        CREATE DATABASE arcade_db;
        CREATE USER arcade_user WITH ENCRYPTED PASSWORD 'your_password';
        GRANT ALL PRIVILEGES ON DATABASE arcade_db TO arcade_user;
        \q
        ```

5.  **Configure Environment Variables:**
    * Create a file named `.env` in the root of your project.
    * Add the following variables, replacing the values with your own:
        ```
        DB_USER=arcade_user
        DB_HOST=localhost
        DB_DATABASE=arcade_db
        DB_PASSWORD=your_password
        DB_PORT=5432
        SESSION_SECRET=a_long_random_string_for_security
        GEMINI_API_KEY=your_google_ai_studio_api_key
        ```

6.  **Run the Server:**
    * For development:
        ```bash
        node server.js
        ```
    * For production (using PM2):
        ```bash
        pm2 start server.js --name arcade
        ```

The application will be running on `http://localhost:3000`.
