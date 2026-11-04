# Asset Service

Vendor and product intelligence: catalog, CPE names and product identifiers, CVE-to-product
associations with affected version ranges, product vulnerability history and vendor analytics.

- Package: `@cve/asset-service`
- Default port: `4004`
- Database: `asset_service` (owned exclusively by this service, role `asset_service`)
- Full documentation: [docs/asset-service.md](../../docs/asset-service.md)

## Endpoints

All under `/api/v1`; reads need `asset:read`, writes `asset:manage`.

| Method             | Path                                          | Description                        |
| ------------------ | --------------------------------------------- | ---------------------------------- |
| GET, POST          | `/vendors`                                    | Search / create vendors            |
| GET, PATCH, DELETE | `/vendors/:vendorId`                          | Vendor                             |
| GET                | `/vendors/:vendorId/products`                 | Products of a vendor               |
| GET                | `/vendors/:vendorId/analytics`                | Vendor vulnerability analytics     |
| GET, POST          | `/products`                                   | Search / create products           |
| GET, PATCH, DELETE | `/products/:productId`                        | Product                            |
| POST, DELETE       | `/products/:productId/cpes[/:cpeId]`          | CPE 2.3 names                      |
| POST, DELETE       | `/products/:productId/identifiers[/:id]`      | purl, SWID, SKU identifiers        |
| GET                | `/products/:productId/vulnerabilities`        | Associated CVEs, ranges, CVE facts |
| PUT, DELETE        | `/products/:productId/vulnerabilities/:cveId` | Analyst-maintained association     |
| GET                | `/products/:productId/vulnerability-history`  | Association timeline               |
| GET                | `/cve-associations`                           | Associations across the catalog    |
| GET                | `/health/live`, `/health/ready`, `/health`    | Health probes                      |

Events: consumes `intelligence.cve-observation.recorded` and `cve.record.*`; publishes
`asset.vendor.*`, `asset.product.*` and `asset.cve-association.*` through the outbox.

## Scripts

```bash
pnpm --filter @cve/asset-service dev               # watch mode (reads ../../.env)
pnpm --filter @cve/asset-service test              # unit + HTTP tests
pnpm --filter @cve/asset-service test:integration  # PostgreSQL integration tests
pnpm --filter @cve/asset-service typecheck
pnpm --filter @cve/asset-service prisma:migrate:deploy
```
