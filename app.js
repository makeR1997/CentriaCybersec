 -0,0 +1,47 
import { Hono } from "https://deno.land/x/hono/mod.ts";
import client from "./db/db.js";
import * as bcrypt from "https://deno.land/x/bcrypt/mod.ts"; // For password hashing

const app = new Hono();

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
