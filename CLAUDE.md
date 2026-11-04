# CVE Intelligence Platform — Master Development Specification

## 1. Project Overview

Build a professional, self-hosted CVE Intelligence Platform for vulnerability intelligence, vulnerability analysis, exploit tracking, automated Proof-of-Concept (PoC) discovery, secure artifact downloading, and centralized repository management.

The platform must support:
- CVE collection and enrichment.
- CVSS v3.1 and v4.0 analysis.
- CWE classification.
- Vendor and product intelligence.
- CISA KEV and EPSS integration.
- Public PoC discovery.
- Automated, controlled PoC downloading.
- Secure artifact storage using MinIO.
- Exploit intelligence and CVE relationships.
- Advanced search, dashboards, reporting, and notifications.
- Multi-user access control and audit logging.

## 2. Non-Negotiable Development Rules

1. Use TypeScript for all application code.
2. Do not use Python anywhere in application code, workers, scripts, or deployment automation.
3. All UI content must be English.
4. All source-code identifiers, database identifiers, API names, and documentation must be English.
5. Use strict TypeScript. Avoid `any`.
6. Use modular, testable, maintainable architecture.
7. Never expose secrets, credentials, or API keys in frontend code.
8. Validate all external input.
9. Use structured logging.
10. Write automated tests for business-critical functionality.
11. Do not implement placeholder functionality and report it as complete.
12. Do not silently ignore errors.
13. Use database migrations for schema changes.
14. Never execute downloaded PoC files.
15. Never automatically run exploit code.
16. Do not expose quarantined artifacts to ordinary users.

## 3. Technology Stack

### Frontend
- Next.js
- React
- TypeScript
- Tailwind CSS
- shadcn/ui
- TanStack Query
- Recharts
- React Hook Form
- Zod

### Backend
- NestJS
- TypeScript
- REST API
- RabbitMQ for service events
- BullMQ for background jobs
- Redis for queues and caching

### Data
- PostgreSQL
- Prisma ORM
- OpenSearch for advanced search
- MinIO for object storage

### Infrastructure
- Docker Compose
- Nginx
- Keycloak
- Prometheus
- Grafana
- Pino

### Testing
- Vitest
- Supertest
- Playwright

## 4. Architecture

Use a microservices architecture with independently deployable services.

Services:

1. API Gateway
2. Identity Service
3. CVE Service
4. Intelligence Service
5. Asset Service
6. PoC Service
7. Download Service
8. Exploit Service
9. Reporting Service
10. Notification Service

Each service must have:
- Its own module structure.
- Its own business logic.
- Its own data ownership.
- Its own database migrations.
- Its own health endpoint.
- Its own tests.
- Clearly defined API and event contracts.

Services must not directly access another service's database tables.

Use RabbitMQ for domain events and asynchronous service communication. Use BullMQ for retryable and scheduled background jobs.

Use an outbox pattern for reliable publication of important domain events.

## 5. External Intelligence Sources

Implement independent adapters for:

- NVD API
- MITRE CVE
- CISA KEV
- EPSS
- GitHub
- Exploit-DB

Each integration must support:
- Configurable credentials.
- Rate limiting.
- Pagination.
- Retry with exponential backoff.
- Timeout handling.
- Source attribution.
- Incremental synchronization.
- Deduplication.
- Synchronization logs.

Never assume that a source is available or that its API terms permit unrestricted redistribution.

## 6. CVE Intelligence Requirements

Store and process:
- CVE ID.
- Description.
- Publication date.
- Last modification date.
- CVSS v3.1.
- CVSS v4.0.
- CVSS vector strings.
- Severity.
- CWE identifiers.
- Affected vendors.
- Affected products.
- Affected version ranges.
- References.
- CISA KEV status.
- EPSS score and percentile.
- Source provenance.

Preserve original source data where licensing and retention policies permit.

Do not overwrite source-specific metrics without retaining their source and observation time.

## 7. PoC Management Requirements

Implement:
- PoC discovery.
- Source repository tracking.
- CVE association.
- Download scheduling.
- Download history.
- SHA-256 calculation.
- Duplicate detection.
- MinIO storage.
- Artifact inspection.
- Quarantine management.
- Verification status.
- Version tracking.

Every artifact must record:
- Artifact ID.
- Related CVE ID.
- Source URL.
- Source repository.
- Original filename.
- Generated storage key.
- SHA-256 hash.
- File size.
- MIME type.
- Discovery timestamp.
- Download timestamp.
- Scanner results.
- Verification status.
- Artifact lifecycle status.

All downloaded content is untrusted.

Apply:
- Source allowlists.
- URL and redirect validation.
- DNS resolution and private-network blocking.
- Response size limits.
- Download timeouts.
- Content type validation.
- SHA-256 integrity checks.
- Malware scanning.
- Quarantine before release.

Never execute scripts, binaries, macros, or exploit code.

Never automatically extract archives.

Do not allow user-controlled filenames to become filesystem paths or object keys.

## 8. Security

Implement:
- Keycloak-based authentication.
- Role-Based Access Control.
- API rate limiting.
- Input validation.
- Secure secret management.
- Audit logging.
- TLS.
- Secure HTTP headers.
- CORS restrictions.
- Database least-privilege access.
- MinIO least-privilege credentials.
- Container resource limits.
- Dependency vulnerability scanning.

Recommended roles:
- Super Admin
- Administrator
- Security Analyst
- Vulnerability Researcher
- Viewer

## 9. Frontend Requirements

Build an English-language professional security intelligence interface.

Main navigation:
- Overview
- CVE Explorer
- Vulnerability Analysis
- PoC Repository
- Exploit Intelligence
- Vendors & Products
- Threat Intelligence
- Download Manager
- Data Sources
- Reports
- User Management
- Audit Logs
- Settings

The interface must include:
- Dark theme.
- Responsive layouts.
- Search and advanced filters.
- Pagination.
- Sorting.
- Loading states.
- Empty states.
- Error states.
- Confirmation dialogs for sensitive actions.
- Clear artifact security statuses.

Do not display fabricated statistics or fake source synchronization results.

## 10. API Standards

- Version all public API endpoints under `/api/v1`.
- Use consistent response structures.
- Use appropriate HTTP status codes.
- Validate request and response schemas.
- Implement pagination.
- Generate OpenAPI documentation.
- Add request correlation IDs.
- Use idempotency keys for critical operations.

## 11. Database Standards

- Use PostgreSQL.
- Use Prisma ORM.
- Use UUID primary keys.
- Use UTC timestamps.
- Use explicit database indexes.
- Use unique constraints for external identifiers.
- Use migrations.
- Preserve data provenance.
- Avoid cross-service database joins.
- Use stable external identifiers for service relationships.

## 12. Development Workflow

Before implementing a feature:

1. Read this file.
2. Inspect the existing project.
3. Review the relevant service contracts.
4. Identify database changes.
5. Write an implementation plan.
6. Implement the feature.
7. Write tests.
8. Run linting.
9. Run type checking.
10. Run tests.
11. Update documentation.

Never replace existing working functionality without understanding its dependencies.

Do not rewrite the entire repository when implementing a single feature.

## 13. Completion Criteria

A task is complete only when:
- Implementation exists.
- TypeScript compilation succeeds.
- Tests pass.
- Relevant migrations are included.
- Security requirements are addressed.
- Documentation is updated.
- No known critical errors remain.

Report completed work separately from planned or unfinished work.

## 14. Delivery Strategy

Build in the following order:

Phase 0: Monorepo and infrastructure foundation.

Phase 1: Authentication, authorization, and audit logging.

Phase 2: CVE Service and database.

Phase 3: NVD, MITRE, CISA, and EPSS integrations.

Phase 4: Asset and product intelligence.

Phase 5: PoC discovery and metadata management.

Phase 6: Secure automated downloads and MinIO storage.

Phase 7: Exploit intelligence.

Phase 8: Dashboard and analytics.

Phase 9: Reporting and notifications.

Phase 10: Production hardening, backup, monitoring, and deployment.

Do not begin later phases until their required dependencies are working and tested.

## 15. Final Objective

Deliver a production-oriented, self-hosted CVE Intelligence Platform using TypeScript throughout, with secure automated PoC collection, comprehensive vulnerability intelligence, and a maintainable microservices architecture.
