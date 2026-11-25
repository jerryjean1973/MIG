import { expect, it } from "vitest";
import { z } from "zod";
import { migToolSchemaProperties } from "../server/mig/ms5/tool-schema";
it("preserves native and transported schema property inventories", () => {
  const native = z.object({ source: z.string(), version: z.string().optional() });
  const transported = { type: "object", properties: { source: { type: "string" }, version: { type: "string" } } };
  expect(migToolSchemaProperties(native)).toEqual(migToolSchemaProperties(transported));
});
