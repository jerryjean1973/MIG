import type { Request, Response, NextFunction } from "express";
import { requireMigPool } from "../db";

let readyUntil = 0;
export async function requireEnterpriseSchemaReady(_req: Request, res: Response, next: NextFunction) {
  try {
    if (readyUntil <= Date.now()) {
      const result = await requireMigPool().query(
        "SELECT to_regclass('mig_principals') AS principals, to_regclass('mig_clients') AS clients, to_regclass('mig_standalone_sessions') AS sessions",
      );
      if (!result.rows[0]?.principals || !result.rows[0]?.clients || !result.rows[0]?.sessions) {
        throw new Error("MIG_MIGRATIONS_REQUIRED");
      }
      readyUntil = Date.now() + 10_000;
    }
    next();
  } catch { res.status(503).json({ error: "MIG_MIGRATIONS_REQUIRED" }); }
}
