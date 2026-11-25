# MIG — standalone MCP Intent Gateway

An independently built Node.js/PostgreSQL application with the MIG operator
interface, client registration, credential ceilings, intent governance, MCP
transport, delegation, audit, security review and retained MIG history.

This checkout does **not** require access to the combined application's source,
a Git submodule or a BRIPe engine checkout to install, build or start.
BRIPe computation and Corporate Brain authority remain external services.
Their absence is an explicit unavailable state, never an invented permission,
empty canonical catalog or simulated structural result.

## Requirements and quick start

- Node.js 22.12 or newer; pnpm 10.26.1.
- A **dedicated** PostgreSQL database.
- An OpenID Connect provider with an explicitly assigned MIG administrator role.
- An authorized canonical-owner host with the bridge described below.

```sh
pnpm install --frozen-lockfile
cp config.env.example .env
# Configure your environment privately. Never commit .env.
pnpm db:migrate
pnpm build
NODE_ENV=production pnpm start
```

For development, use `pnpm dev`. It serves Vite through the same Express origin;
API requests use relative URLs. `/` and `/mig` are application entry points,
`/api/health` reports configuration, and `/api/mcp` is the governed MCP transport.
An unconfigured server shows the setup state and rejects protected operations.

## Administrator sign-in

Set `MIG_PUBLIC_ORIGIN` to the application's exact external HTTPS origin and
register its `/api/auth/callback` URL with your identity provider.

`MIG_TENANT_ID` is the internal, fixed MIG tenant. `MIG_OIDC_TENANT_REF` is the
expected identity-provider tenant claim; it need not equal the internal ID.
The default claim names are `tenant_id` and `roles`. For Entra, configure the
appropriate tenant claim, normally `tid`, and an application role such as
`MIG.Admin`. Assign that role explicitly to administrators.

Sign-in verifies issuer, audience, signature, nonce, state, PKCE, tenant and role.
Opaque sessions are stored as token hashes in the dedicated database, expire
within 15 minutes, and use secure HttpOnly cookies. Writes require the configured
same origin. Logout acknowledges database revocation before reporting success.
Browser-provided tenant and user headers do not establish administrator identity.

Client identities, their grants and authority-provider mappings are separately
registered through MIG's existing governance process. An administrator login
does not automatically grant a client any capability.

## Canonical-owner connection

`MIG_OWNER_BRIDGE_URL` must be the owner's HTTPS
`/api/mig/owner-bridge/v1` endpoint. Both hosts need the same private signing
secret of at least 32 characters, and the owner must explicitly allow the
configured MIG tenant.

The protocol binds each response to the exact request, tenant and nonce,
requires durable replay protection and does not retry uncertain operations.
It transports native validation/admission decisions and results; it does not
replace their owners with local implementations.

On the existing canonical-owner host:

1. Install `server/mig/mig-owner-bridge.ts` and
   `shared/contracts/mig-owner-bridge-v1.ts` from this repository.
2. Install `integrations/native-owner-provider.ts.example` as
   `server/mig/mig-native-owner-provider.ts`. Its imports intentionally refer
   to that host's **existing** native owners, not to this application's remote
   facades.
3. Apply `integrations/owner-bridge-nonces.sql` to the owner's database.
4. Register the provider before that host's general JSON body parser, using its private configuration and
   durable database connection:

```ts
registerNativeMigOwnerProvider(app, {
  secret: configuredPrivateBridgeSecret,
  allowedTenantIds: new Set(explicitlyAllowedTenantIds),
  claimNonce: createPostgresMigOwnerNonceClaimer(ownerDatabasePool),
});
```

The registration is intentionally not automatic, and must not be installed
recursively on the standalone MIG server. The owner's normal private
authorization, resource policies and producer configuration remain required.
Public protocol declarations in `shared/protocol` are types only, not engine
implementations or canonical stores.

## Persistence and existing installations

`MIG_DATABASE_URL` is mandatory for database operations. The application never
falls back to another application's `DATABASE_URL`. Committed migrations create
the MIG and required generic identity/audit tables; they contain no records.
Applied migrations are hashed and may not be edited in place.

No existing credentials, principals, mappings, grants, tenant records, documents,
uploads or private keys are included. This is not an automatic migration of a live
MIG installation. Preserve those private records through their authorized owners;
do not replace existing client identities or silently re-enroll them.

`MIG_ATTESTATION_SECRET` and `MIG_DELEGATION_SECRET` configure the existing MIG signing
paths. Individual agent ticket secrets are created during agent registration.
`MCP_RESOURCE_URL` is the public HTTPS `/api/mcp` URL used when provisioning
remote-client configurations. Optional Microsoft authority mappings and security
review providers retain their existing configuration requirements.

## Verification

```sh
pnpm build
pnpm test
pnpm check
```

The build rejects private engine implementation paths in its emitted backend
source graph. Focused tests exercise transport integrity, replay rejection,
tenant binding, native wire values and schema property conservation. Test
fixtures are not native BRIPe execution or production identity-provider proof.
**Known limitation:** `pnpm check` is not yet green. Retained MIG source and its
projected declarations report strict typing diagnostics. The passing build and
focused/runtime tests do not constitute a clean TypeScript check.

Active organization identity is read from the canonical owner, not invented or
seeded into MIG's empty database. Platform-only administration is unavailable to
an organization administrator; configure cross-platform mappings at their owner.

No application publishing, database transfer, provider enrollment or production
connection is performed by installing or pushing this repository.
