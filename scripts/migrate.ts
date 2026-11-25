import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import pg from "pg";

if (!process.env.MIG_DATABASE_URL || !process.env.MIG_TENANT_ID) {
  throw new Error("MIG_DATABASE_URL_AND_TENANT_ID_REQUIRED");
}
const client = new pg.Client({ connectionString: process.env.MIG_DATABASE_URL });
await client.connect();
try {
  await client.query("SELECT pg_advisory_lock(674350192)");
  await client.query(`CREATE TABLE IF NOT EXISTS mig_standalone_migrations (
    name text PRIMARY KEY, hash text NOT NULL, applied_at timestamptz NOT NULL DEFAULT NOW()
  )`);
  const generated = (await readdir("migrations/generated")).filter(name => name.endsWith(".sql")).sort();
  const own = (await readdir("migrations")).filter(name => name.endsWith(".sql")).sort();
  for (const filename of [
    ...generated.map(name => "migrations/generated/" + name),
    ...own.map(name => "migrations/" + name),
  ]) {
    const sql = await readFile(resolve(filename), "utf8");
    const hash = createHash("sha256").update(sql).digest("hex");
    const previous = await client.query("SELECT hash FROM mig_standalone_migrations WHERE name = $1", [filename]);
    if (previous.rows.length) {
      if (previous.rows[0].hash !== hash) throw new Error("MIG_APPLIED_MIGRATION_CHANGED");
      continue;
    }
    await client.query("BEGIN");
    try {
      await client.query(sql);
      await client.query("INSERT INTO mig_standalone_migrations (name, hash) VALUES ($1, $2)", [filename, hash]);
      await client.query("COMMIT");
    } catch {
      await client.query("ROLLBACK");
      throw new Error("MIG_MIGRATION_FAILED:" + filename);
    }
  }
  console.log("MIG migrations applied.");
} finally {
  await client.query("SELECT pg_advisory_unlock(674350192)").catch(() => {});
  await client.end();
}
