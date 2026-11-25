/**
 * server/mig/mig-intent-library.ts
 *
 * Intent Library management — versioned collections of IntentDefinitions.
 * Purely governance/data plumbing; contains no BRIPe/MCP-specific tool
 * names. Adapters (e.g. mig-bripe-adapter.ts) seed concrete intents through
 * these generic functions.
 */

import { storage } from "../storage";
import type {
  MigIntentLibrary,
  InsertMigIntentLibrary,
  MigIntentDefinition,
  InsertMigIntentDefinition,
} from "@shared/schema";

export async function createIntentLibrary(data: InsertMigIntentLibrary): Promise<MigIntentLibrary> {
  const existing = await storage.getMigIntentLibrary(data.libraryId);
  if (existing) return existing;
  return storage.createMigIntentLibrary(data);
}

export async function publishIntentLibrary(libraryId: string): Promise<MigIntentLibrary | undefined> {
  return storage.updateMigIntentLibraryStatus(libraryId, "published");
}

export async function listIntentLibraries(): Promise<MigIntentLibrary[]> {
  return storage.listMigIntentLibraries();
}

export async function getIntentLibrary(libraryId: string): Promise<MigIntentLibrary | undefined> {
  return storage.getMigIntentLibrary(libraryId);
}

export async function createIntentDefinition(data: InsertMigIntentDefinition): Promise<MigIntentDefinition> {
  const existing = await storage.getMigIntentDefinition(data.intentId);
  if (existing) return existing;
  return storage.createMigIntentDefinition(data);
}

/**
 * Upsert an intent definition — creates it if it doesn't exist, updates all
 * mutable fields if it does. Used by the seed function so re-seeding
 * always reflects the canonical current definition (not the stale first-run
 * snapshot that `createIntentDefinition`'s early-return would otherwise keep).
 */
export async function upsertIntentDefinition(data: InsertMigIntentDefinition): Promise<MigIntentDefinition> {
  const existing = await storage.getMigIntentDefinition(data.intentId);
  if (!existing) {
    return storage.createMigIntentDefinition(data);
  }
  const updated = await storage.updateMigIntentDefinition(data.intentId, {
    libraryId: data.libraryId,
    name: data.name,
    description: data.description,
    allowedCapabilityIds: data.allowedCapabilityIds,
    deniedCapabilityIds: data.deniedCapabilityIds,
    allowedToolNames: data.allowedToolNames,
    deniedToolNames: data.deniedToolNames,
    domainScope: data.domainScope,
    packageScope: data.packageScope,
    riskZone: data.riskZone,
    payloadClasses: data.payloadClasses,
    requiresHumanApproval: data.requiresHumanApproval,
    requiresEvidence: data.requiresEvidence,
    requiresManifest: data.requiresManifest,
    status: data.status,
  });
  return updated ?? existing;
}

export async function getIntentDefinition(intentId: string): Promise<MigIntentDefinition | undefined> {
  return storage.getMigIntentDefinition(intentId);
}

export async function listIntentDefinitions(libraryId?: string): Promise<MigIntentDefinition[]> {
  return storage.listMigIntentDefinitions(libraryId);
}

export async function deprecateIntentDefinition(intentId: string): Promise<MigIntentDefinition | undefined> {
  return storage.updateMigIntentDefinition(intentId, { status: "deprecated" });
}

export async function activateIntentDefinition(intentId: string): Promise<MigIntentDefinition | undefined> {
  return storage.updateMigIntentDefinition(intentId, { status: "active" });
}
