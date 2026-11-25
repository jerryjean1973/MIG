import { z } from "zod";
export declare const DSPBindingSchema: any;
export declare const DSPCollaborationSchema: any;
export declare const DSPRequestSchema: any;
export type EnterpriseDSPRequest = z.infer<typeof DSPRequestSchema>;
