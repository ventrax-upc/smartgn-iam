# Service overview

IAM provides verified-purchase account provisioning, password activation/recovery/change, profiles, current JWT sessions and per-meter delegated permissions. Global roles are USER and SUPERADMIN. Principal and delegated describe account kinds.

The services run locally in Docker with independent PostgreSQL databases and a real EMQX broker. Billing, Notifications and Telemetry integrations use labeled local contract doubles.

- [Architecture](architecture.md)
- [User-story traceability](traceability.md)
- [Executed verification](verification.md)

Runtime OpenAPI documents the available operations. The verification record distinguishes executed application/broker checks from simulated integrations and unverified provider behavior.
