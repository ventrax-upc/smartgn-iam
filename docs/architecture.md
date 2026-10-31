# Architecture

IAM owns identities, credentials, profiles, active sessions and delegated permissions. It stores its data in an independent PostgreSQL database and communicates with Installation and Billing through authenticated HTTP contracts.

## Service responsibilities

| Area | Current design |
| --- | --- |
| Platform | Java 25, Spring Boot, independent PostgreSQL databases and local Docker execution |
| Identity | USER and SUPERADMIN global roles; principal/delegated account kinds; pending, active and disabled account states |
| Credentials | Separate password credentials, purpose-bound one-time tokens and current session versions |
| Delegation | Principal-owned subusers and independently revocable meter/function grants |
| Integration | Service credentials, transactional inbox/outbox, deduplication and correlation; no shared database access |

Public REST contracts expose resource operations and validation. A supply-point UUID identifies a stable logical meter. Device replacement does not change that meter's permissions.

## Authorization and service boundaries

IAM verifies meter ownership through Installation's private read contract. That contract resolves local data without calling IAM. Installation verifies JWT signatures, issuer, audience and expiry, then introspects current identity and session state. Delegated reads additionally require a current function grant. Dependency failures deny authorization.

Properties and supply points belong to the principal. Delegates can access granted meter functions without acquiring property administration rights. Automatic assignment uses a service audit marker rather than an IAM login account.

The integrated composition connects real IAM, Installation, Support and Billing services through the Gateway. Notification delivery and Telemetry metadata use explicitly labeled local fixtures; they do not provide productive notification delivery or telemetry ingestion.

## Identity model and persistence

The domain contains `UserAccount`, `PasswordCredential`, `OneTimeToken`, `UserProfile`, `Delegation` and `MeterPermissionGrant`. Domain objects have no Spring, JSON or persistence annotations. Repository ports and JDBC adapters connect these models to the `iam` PostgreSQL schema.

Purchase-provisioned and delegated accounts start pending without a password credential. Activation checks account eligibility, creates the credential and consumes the activation token atomically. Recovery requests and password mutations lock the account before recovery tokens. This ordering serializes concurrent requests and ensures one current recovery link.

Delegated permissions are checked from current records rather than JWT claims. Billing owns plans and paid-through periods. Sensitive activation and recovery messages use an encrypted delivery queue; general domain events contain no passwords or one-time secrets. Delivery submission and provider delivery are distinct states.

Flyway initializes the database from a single English SQL schema. Credentials, profile data, assignment evidence and audit records have independent persistence responsibilities.
