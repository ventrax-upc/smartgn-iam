# IAM API and integration contracts

Public resources use `/api/v1`. Schema details and response codes are available in `openapi.json` and runtime `/v3/api-docs`. The default protected scheme is `bearerAuth`; private service input uses the separate `serviceAuth` scheme.

| Method | Resource | Rule |
| --- | --- | --- |
| POST | `/auth/activate-password` | Anonymous; `{activationToken,newPassword}`; 204 on one eligible single-use activation |
| POST | `/auth/sign-in` | Anonymous; active account and valid password; current JWT without a plan claim |
| POST | `/auth/forgot-password` | Anonymous; uniform 202 whether an eligible account exists or not |
| POST | `/auth/reset-password` | Anonymous; recovery-purpose token only; consumes link and invalidates old sessions |
| POST | `/auth/change-password` | Current session plus correct current password; invalidates old sessions |
| GET/PUT | `/profiles/me` | Only the authenticated account's allowed profile fields |
| POST/GET | `/subusers` | Active principal USER only; unique email; no default grants |
| PUT | `/subusers/{subuserId}/grants` | `{meterId,permissions[]}` replaces only that meter's functions |
| GET/DELETE | `/subusers/{subuserId}/grants/{meterId}` | Principal-owned delegation; DELETE preserves other meters and grant history |

The six functions are VIEW_CONSUMPTION, VIEW_HISTORY, VIEW_ALERTS, USE_REPORTS, USE_TICKETS and USE_VISITS. Financial and subuser-management functions are rejected. Revoked functions stop authorizing new requests even with the same JWT. A function grant does not replace a required Pro entitlement on the principal.

## Private contracts owned by IAM

All `/internal/v1/**` routes require the service credential; user JWTs do not authorize them. They must remain outside public gateway routing.

- POST `/accounts/purchase-confirmations`: `{eventId,purchaseOrderId,email,firstName,lastName,confirmed}`. Only a trusted verified initial-purchase result with `confirmed=true` provisions a pending principal. Same receipt is idempotent; conflicting identities are rejected. Browser payment returns are not proof. Actual Niubiz verification remains Billing's responsibility.
- POST `/sessions/introspect`: `{token}`. Validates current cryptography, account state, role and session version; returns account context without credentials or plan authority.
- GET `/accounts/{id}` and `/accounts/{id}/grants`: current service-only identity context and active delegated meter/function snapshot.
- POST `/authorizations/check`: `{accountId,meterId,function,requiresPro}` returns `{allowed}`. The trusted consuming service sets whether its operation requires Pro; unknown functions are denied. IAM rechecks principal ownership with Installation. The entitlement adapter is a labeled local Billing double until a real contract exists.

## Messages and sensitive delivery

General domain events contain an event ID, event type, aggregate ID and correlation ID. They are durable and may be submitted more than once; consumers deduplicate by event ID. AccountProvisioned, AccountActivated, CredentialsChanged and MeterPermissionsChanged do not contain passwords or one-time secrets.

Activation/recovery delivery is a separate AES-GCM-protected queue. Only token verifiers are stored in `one_time_tokens`. Submission uses a protected internal HTTP adapter and a stable Idempotency-Key; submission success is distinct from final provider delivery. Tokens/links are never logged or sent through the general event channel. Failed submissions retain retryable state.

The local adapter's `/local-contracts/notifications`, entitlement and event-sink routes belong to the development fixture. They are not published as definitive interfaces of future services. X-Correlation-ID is propagated across current HTTP calls and durable messages.
