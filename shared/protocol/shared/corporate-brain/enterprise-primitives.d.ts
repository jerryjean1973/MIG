import { z } from "zod";
export declare const ENTERPRISE_PRIMITIVES: readonly ["GOVERN", "OPERATE", "COMPETE", "PROTECT", "ADAPT", "SURVIVE"];
export declare const EnterprisePrimitiveSchema: any;
export type EnterprisePrimitive = z.infer<typeof EnterprisePrimitiveSchema>;
