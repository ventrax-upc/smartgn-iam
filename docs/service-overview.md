# Service overview

IAM provides verified-purchase account provisioning, password activation/recovery/change, profiles, current JWT sessions and per-meter delegated permissions. Global roles are USER and SUPERADMIN. Principal and delegated describe account kinds.

The local Docker environment uses independent PostgreSQL databases and an authenticated EMQX broker. The bundled composition provides labeled development doubles for Billing, Notifications and Telemetry. The integrated Payments environment connects the actual Billing service through its authenticated HTTP contracts.

- [Architecture](architecture.md)
- [API contracts](contracts.md)
- [Exported OpenAPI](openapi.json)

Runtime OpenAPI documents request and response schemas. Each service owns its data and communicates through authenticated contracts and events.
