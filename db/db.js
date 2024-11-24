@@ -0,0 +1,14 @@
import { Client } from "https://deno.land/x/postgres/mod.ts";

// Set up PostgreSQL client connection
const client = new Client({
  user: "postgres",
  database: "postgres",
  hostname: "localhost",
  password: "Secret1234!",
  port: 5432,
});

await client.connect();

export default client;
