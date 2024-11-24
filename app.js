 -0,0 +1,47 
import { Hono } from "https://deno.land/x/hono/mod.ts";
import client from "./db/db.js";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts"; // For password hashing

const app = new Hono();

const express = require('express');
const helmet = require('helmet');
const xss = require('xss-clean');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const bodyParser = require('body-parser');
const path = require('path');
const app = express();

// Middleware for parsing request bodies
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// 1. Set Security Headers using Helmet
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'"],
        "img-src": ["'self'"],
        "connect-src": ["'self'"],
        "frame-ancestors": ["'none'"], // Anti-clickjacking
      },
    },
    frameguard: { action: 'deny' }, // Anti-clickjacking
    xssFilter: true, // XSS protection
    noSniff: true, // Prevent MIME sniffing
  })
);

// 2. Input Validation and Sanitization
app.use(xss()); // Prevent XSS attacks by sanitizing user input

// 3. Protect against HTTP Parameter Pollution
app.use(hpp());

// 4. Rate Limiting to Prevent Abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

// 5. Restrict File Access to Prevent Path Traversal
app.get('/files/:filename', (req, res, next) => {
  const filePath = path.join(__dirname, 'safe-folder', path.basename(req.params.filename));
  res.sendFile(filePath, (err) => {
    if (err) {
      res.status(403).send('Access denied');
    }
  });
});

// 6. Example SQL Injection Mitigation (use an ORM or parameterized queries)
const mysql = require('mysql2');
const db = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'cybersec',
});

// Example query with parameterized input
app.post('/user', (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
  db.execute(query, [username, password], (err, results) => {
    if (err) {
      res.status(500).send('Error occurred');
    } else {
      res.json(results);
    }
  });
});

// Example User-Agent Filtering
app.use((req, res, next) => {
  const allowedUserAgents = [/Mozilla/, /Chrome/, /Safari/];
  const userAgent = req.headers['user-agent'];
  if (!allowedUserAgents.some((regex) => regex.test(userAgent))) {
    return res.status(400).send('Unsupported user agent');
  }
  next();
});

// Start the server
app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});


// Serve the registration form
app.get('/register', async (c) => {
  return c.html(await Deno.readTextFile('./views/register.html'));
});

// Handle user registration (form submission)
app.post('/register', async (c) => {
  const body = await c.req.parseBody();

  const username = body.username;
  const password = body.password;
  const birthdate = body.birthdate;
  const role = body.role;

  try {
    // Hash the user's password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Insert the new user into the database
    const result = await client.queryArray(
      `INSERT INTO zephyr_users (username, password_hash, role, birthdate)
       VALUES ($1, $2, $3, $4)`,
      [username,
      hashedPassword,
      role,
      birthdate]
    );

    // Success response
    return c.text('User registered successfully!');
  } catch (error) {
    console.error(error);
    return c.text('Error during registration', 500);
  }
});

Deno.serve(app.fetch);

// The Web app starts with the command:
// deno run --allow-net --allow-env --allow-read --watch app.js
