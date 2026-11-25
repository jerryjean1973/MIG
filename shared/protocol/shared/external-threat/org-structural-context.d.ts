export interface OrgStructuralContext {
    /**
     * Canonical organization identifier — used for CSSL cross-reference.
     * Typically the Corporate Brain entity ID or VendorGate entity key.
     */
    organization_id: string;
    /**
     * Technology inventory — CPE strings (e.g. "cpe:2.3:a:apache:log4j:2.14.1:*")
     * or normalized product names (e.g. "Microsoft Exchange Server 2019").
     * Used to match against observation.affected_technologies.
     */
    technology_inventory: string[];
    /**
     * Externally exposed services — protocol:port or service name strings.
     * Examples: "HTTPS:443", "RDP:3389", "SMB:445", "VPN:IPSec".
     * A matching exposed service elevates relevance for infrastructure-targeting observations.
     */
    exposed_services: string[];
    /**
     * Primary industry sector — NAICS code or normalized sector label.
     * Examples: "healthcare", "financial_services", "energy", "manufacturing".
     * Matched against observation.affected_sectors.
     */
    sector: string;
    /**
     * Geographic regions where this org operates — ISO 3166-1 alpha-2 or normalized labels.
     * Examples: ["CA", "US"], ["europe", "north_america"].
     * Matched against observation.affected_regions.
     */
    geography: string[];
    /**
     * Vendor and third-party dependencies — product or vendor names.
     * Examples: ["Microsoft", "Cisco", "Palo Alto Networks"].
     * A matching vendor dependency elevates relevance for supply-chain observations.
     */
    vendor_dependencies: string[];
    /**
     * Identity and authentication stack — IdP / SSO product identifiers.
     * Examples: ["Okta", "Azure AD", "Active Directory"].
     * Used to match credential-theft and identity-related observations.
     */
    identity_stack: string[];
    /**
     * Cloud service providers in use — provider names or service labels.
     * Examples: ["AWS", "Azure", "GCP", "on-premise"].
     */
    cloud_providers: string[];
    /**
     * Known vulnerability IDs that have been confirmed present in the org.
     * Format: CVE IDs (e.g. "CVE-2021-44228").
     * Sourced from CMDB, vulnerability scanner, or manual attestation.
     * Matched against observation.cve_ids — direct CVE match is the highest-confidence
     * relevance signal.
     */
    known_vulnerabilities: string[];
    /**
     * Defensive controls currently deployed and confirmed operational.
     * Examples: ["EDR", "MFA", "NDR", "SIEM", "WAF", "email_gateway", "backup_tested"].
     * Used by the pressure computer to reduce pressure for mitigated attack vectors.
     */
    defensive_controls: string[];
}
