# SmartGN IAM

## Overview

Manages account activation, sessions, profiles and delegated access. Private contracts let other services check identity and meter permissions.

**Stack**  Java 25, Spring Boot, PostgreSQL, Flyway.

## Run locally

The [integrated startup guide](https://github.com/ventrax-upc/smartgn-api-gateway/blob/develop/README.md#start-all-13-repositories-locally) covers all 13 repositories. The commands below describe this component.

Requirements are Docker Desktop with the Linux engine and PowerShell 7. Keep the SmartGN repositories as siblings for the integrated stack.

```powershell
./scripts/start-local.ps1
```

Run `./scripts/start-local.ps1 -Integrated` to start all 11 services through the integrated Compose.

| Endpoint | Local URL |
| --- | --- |
| Swagger UI | [Open](http://localhost:8080/swagger-ui/index.html) |
| OpenAPI | [JSON](http://localhost:8080/v3/api-docs) |
| Health | [Open](http://localhost:8080/actuator/health) |

## Configuration

Standalone settings use the variables in `.env.example`. Copy it to an ignored `.env` when the local startup script requires it. Integrated credentials and generated files are stored under `.local` in the Gateway repository.

Password recovery uses a six-digit, single-use code that expires after ten
minutes and allows up to five verification attempts. An unregistered email
returns HTTP 404. The code is delivered asynchronously through the encrypted
delivery queue.

Integrated Compose uses `IAM_EMAIL_MODE=fixture`. In AWS set
`IAM_EMAIL_MODE=resend`, inject `RESEND_API_KEY` as a server-side secret and
set `RESEND_FROM_EMAIL` to a sender on a verified domain. This also routes
IAM activation and legacy recovery emails through Resend.

## Verification

```powershell
./scripts/test.ps1
./scripts/smoke-local.ps1
```

Run the integrated smoke from the Gateway repository to verify cross-service workflows.

## Repository layout

- `src/main` contains the service implementation.
- `src/test` contains service tests.
- `docs` contains service documentation.
- `scripts` contains local startup and verification commands.
- `tools` contains verification helpers and supporting assets.
- `fixtures/db.json` defines demo fixtures for local verification.

## Documentation

- [Local development](docs/local-development.md)
- [Architecture](docs/architecture.md)
- [Contracts](docs/contracts.md)
- [OpenAPI export](docs/openapi.json)
- [Service overview](docs/service-overview.md)

## Acceptance scenarios

See the [Gherkin acceptance scenarios](docs/acceptance/scenarios.gherkin). These are acceptance specifications. Use the verification commands above to run the automated checks.

## License

Distributed under the [MIT License](LICENSE).
