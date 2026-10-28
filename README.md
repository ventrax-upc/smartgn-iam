# SmartGN IAM

Java 25 / Spring Boot 3.5.6 identity service for verified-purchase provisioning, initial password activation, password recovery/change, profiles, current JWT sessions and per-meter delegated permissions. The only global roles are `USER` and `SUPERADMIN`. Principal/delegated is an account kind, not an additional role.

## Local Docker workflow

The recommended complete environment lives in the adjacent [Installation & Device Management repository](https://github.com/ventrax-upc/smartgn-installation-device-management): run `scripts/start-local.ps1` there, followed by its `scripts/smoke-local.ps1`. This starts both actual applications, independent PostgreSQL containers, real EMQX and labeled doubles for future services.

Run this service's complete isolated verification independently:

```powershell
./scripts/test.ps1
```

The script creates a disposable PostgreSQL 18 container, runs Maven `clean verify` with JDK 25 inside Docker and stops only its own generated container. No host JDK is used. `-SkipDatabase` is a development shortcut and is not full acceptance.

For standalone operation, copy `.env.example` to ignored `.env`, supply independent strong database/JWT/service secrets and a Base64 32-byte delivery encryption key, then run `docker compose up -d --build`. Standalone mode does not invent a Notifications service: requests stay encrypted and pending until a secure delivery adapter URL is configured. The optional `local-bootstrap` profile additionally requires `BOOTSTRAP_SUPERADMIN_EMAIL` and a strong `BOOTSTRAP_SUPERADMIN_PASSWORD`; it neither promotes an existing USER nor resets an existing password.

OpenAPI is at `http://localhost:8080/swagger-ui.html`. [API contracts](docs/contracts.md), [architecture and ownership](docs/architecture.md), [traceability](docs/traceability.md) and [validation](docs/verification.md) describe the implemented behavior. The exported specification is [openapi.json](docs/openapi.json).

## Security and boundaries

- There is no public sign-up or user-selected role. A trusted service provisions a pending principal only after a verified initial purchase.
- Activation and recovery tokens have separate purposes, expiry and atomic single-use consumption. Only verifiers are stored with token records.
- Password hashes live in `password_credentials`; domain models have no Spring, JSON or persistence annotations. JDBC implements the repository ports.
- JWT validation requires signature, issuer, `smartgn-api` audience, expiry, subject/account consistency, current account status and session version. Password changes and recovery invalidate previous sessions.
- A delegated USER starts with no permissions. Current grants and principal ownership are checked per meter/function. Delegated accounts cannot administer subusers or financial capabilities.
- Billing owns subscriptions and paid-through periods. IAM emits no authoritative plan claim and exposes no subscription API. Its entitlement integration is a replaceable local test-double adapter.
- Sensitive activation/recovery requests are encrypted in a dedicated delivery queue and are never published through the general domain outbox. HTTP submission is not proof of final email delivery.

The service uses Flyway 11.20.3, Spring Boot 3.5.6 and PostgreSQL 18. [Flyway database reference](https://documentation.red-gate.com/flyway/reference/database-driver-reference/postgresql-database).

See the [service overview](docs/service-overview.md) for a concise description of responsibilities.
