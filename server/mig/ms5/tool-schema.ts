/** Preserve the same property inventory for local Zod and remote JSON Schema.
 * This reads declared schema fields only; it does not infer authority or score. */
export function migToolSchemaProperties(schema: unknown): string[] {
  if (!schema || typeof schema !== "object") return [];
  const value = schema as { properties?: unknown; _def?: { shape?: unknown } };
  if (value.properties && typeof value.properties === "object" && !Array.isArray(value.properties)) {
    return Object.keys(value.properties);
  }
  if (typeof value._def?.shape === "function") {
    const shape = (value._def.shape as () => unknown)();
    return shape && typeof shape === "object" && !Array.isArray(shape) ? Object.keys(shape) : [];
  }
  return [];
}
