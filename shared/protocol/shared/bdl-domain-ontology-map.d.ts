import { type EnterprisePrimitive } from "./corporate-brain/enterprise-primitives";
export interface EnterprisePrimitiveSemanticMapping {
    mapping_id: string;
    mapping_version: string;
    source_domain: string;
    domain_primitive: string;
    enterprise_primitives: readonly EnterprisePrimitive[];
}
