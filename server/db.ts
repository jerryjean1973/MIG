import pg from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import * as schema from "@shared/schema";

/** Dedicated MIG database only. Never fall back to the host application's DB. */
const url = process.env.MIG_DATABASE_URL;
export const pool = url ? new pg.Pool({
  connectionString: url, max: 8, connectionTimeoutMillis: 10_000,
  idleTimeoutMillis: 30_000, statement_timeout: 30_000,
}) : undefined;
const unavailable = () => { throw new Error("MIG_DATABASE_NOT_CONFIGURED"); };
export const db = pool ? drizzle(pool, { schema }) :
  new Proxy({} as ReturnType<typeof drizzle<typeof schema>>, { get: unavailable });
export function requireMigPool(): pg.Pool {
  if (!pool) throw new Error("MIG_DATABASE_NOT_CONFIGURED");
  return pool;
}
pool?.on("error", () => {
  console.error("MIG_DATABASE_POOL_ERROR"); // Never log connection strings or query payloads.
});
