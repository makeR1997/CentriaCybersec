import { Hono } from "https://deno.land/x/hono/mod.ts";
import client from "./db/db.js";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts"; // For password hashing
import { xss } from "https://deno.land/x/hono_xss/mod.ts"; // For XSS protection
import { logger } from "https://deno.land/x/hono_logger/mod.ts"; // Logging middleware
import { basicAuth } from "https://deno.land/x/hono/middleware/basic-auth/index.ts"; // Rate limiting alternative
import { limiter } from "https://deno.land/x/hono_rate_limiter/mod.ts";

// Initialize Hono app
const app = new Hono();

// Middleware: Add secure headers
app.use("*", (c, next) => {
  c.header("Content-Security-Policy", "default-src 'self'");
  c.header("X-Frame-Options", "DENY");
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-XSS-Protection", "1; mode=block");
  return next();
});

// Middleware: Logging
app.use("*", logger());

// Middleware: XSS Protection
app.use("*", xss());

// Middleware: Rate Limiting using hono_rate_limiter
app.use(
  "*",
  limiter({
    max: 100, // Maximum requests
    windowMs: 15 * 60 * 1000, // Time window in milliseconds (15 minutes)
  })
);

// Serve the registration form
app.get("/register", async (c) => {
  try {
    return c.html(await Deno.readTextFile("./views/register.html"));
  } catch (error) {
    console.error("Error reading the register form:", error);
    return c.text("Error loading the registration form", 500);
  }
});

// Handle user registration (form submission)
app.post("/register", async (c) => {
  const body = await c.req.parseBody();

  // Input sanitization
  const username = body.username.trim();
  const password = body.password.trim();
  const birthdate = body.birthdate.trim();
  const role = body.role.trim();

  try {
    // Hash the user's password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Use parameterized queries to prevent SQL injection
    const result = await client.queryArray(
      `INSERT INTO zephyr_users (username, password_hash, role, birthdate)
       VALUES ($1, $2, $3, $4)`,
      [username, hashedPassword, role, birthdate]
    );

    // Success response
    return c.text("User registered successfully!");
  } catch (error) {
    console.error("Error during registration:", error);
    return c.text("Error during registration", 500);
  }
});

// Example route to test server functionality
app.get("/", (c) => c.text("Server is running securely!"));

// Start the server
Deno.serve(app.fetch);

// To run the app, use the command:
// deno run --allow-net --allow-env --allow-read --watch app.js
