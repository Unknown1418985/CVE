# Backup and disaster recovery

This runbook covers what the platform stores, how it is backed up, how to verify backups and how
to recover from the loss of a component or of the whole host. The tooling lives in
[`infra/backup`](../infra/backup) (POSIX shell around `docker compose`, `pg_dump`/`pg_restore`,
`mc` and [age](https://age-encryption.org)).

## Recovery objectives

| Objective                     | Target with the provided tooling                                           | How to improve it                                                                |
| ----------------------------- | -------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| RPO (data you can lose)       | Time since the last backup set. With the recommended hourly schedule: 1 h  | WAL archiving / point-in-time recovery (pgBackRest, WAL-G) and MinIO replication |
| RTO (time to restore service) | About 1 h for a rebuilt host with a few GB of data (measured drill: below) | A warm standby host that restores the latest set continuously                    |
| Backup retention              | `BACKUP_RETENTION_DAYS` (default 14) on the host, longer off-host          | Object-lock (WORM) storage for the off-host copies                               |

These are single-host targets. The platform has no replication or high availability yet
(see the [production readiness report](production-readiness.md)).

## What is stored where

| Data                                             | Store                          | Backed up        | Notes                                                                                    |
| ------------------------------------------------ | ------------------------------ | ---------------- | ---------------------------------------------------------------------------------------- |
| Service data (CVE, intelligence, assets, PoC, …) | PostgreSQL, one database each  | yes, `pg_dump`   | Includes `_prisma_migrations`, outbox and inbox tables, so events resume after a restore |
| Users, roles, sessions, clients, realm settings  | PostgreSQL `keycloak` database | yes              | Client secrets in this database must match `.env`                                        |
| Audit log                                        | PostgreSQL `identity_service`  | yes              |                                                                                          |
| Quarantined and released PoC artifacts, reports  | MinIO buckets                  | yes, `mc mirror` | Current object versions only; the version history stays in MinIO                         |
| Deployment configuration and every secret        | `.env` on the host             | yes, encrypted   | Only stored when encryption is on                                                        |
| RabbitMQ definitions                             | RabbitMQ                       | yes (reference)  | The provisioner and the services re-declare the topology on start anyway                 |
| Messages in flight                               | RabbitMQ queues                | no               | Producers keep events in their outbox until confirmed; see "Event consistency" below     |
| BullMQ jobs, schedules, caches, idempotency keys | Redis                          | no               | Services re-create their schedules at start; idempotency keys expire anyway              |
| Search index                                     | OpenSearch                     | no               | No service writes to OpenSearch yet                                                      |
| Metrics, dashboards                              | Prometheus, Grafana            | no               | Dashboards and rules are provisioned from this repository; metric history is expendable  |
| TLS certificates                                 | `TLS_CERT_DIR` on the host     | no               | Re-issue them (ACME) or keep them in your secret store                                   |

## Encryption and key handling

Backup sets contain password hashes, every user's data, the audit log and **live malware samples**
from the quarantine bucket. `backup.sh` therefore encrypts every file with age and refuses to run
without `BACKUP_AGE_RECIPIENTS` (only `BACKUP_ALLOW_UNENCRYPTED=true` overrides this, for local
development).

1. Create a key pair on an offline or administrator machine: `age-keygen -o platform-backup.key`.
2. Put the printed public key (`age1…`) into `BACKUP_AGE_RECIPIENTS` on the platform host. Add a
   second recipient (for example a break-glass key held by another person) separated by a comma.
3. Store the private key **off the platform host** (password manager, HSM, sealed envelope). A
   compromised host must not be able to decrypt its own backups.
4. Encrypted sets also stop antivirus software on backup servers from quarantining or deleting the
   malware samples inside them.

## Taking backups

```bash
# On the platform host, from the repository root
infra/backup/backup.sh            # or: pnpm backup
```

The script runs while the platform is up. Each database is dumped in one transaction
(`pg_dump` uses a consistent snapshot); databases are dumped one after another, and objects are
copied after the databases (see "Event consistency"). Output:

```
$BACKUP_DIR/20261108T121144Z/
  postgres/<database>.dump.age    one per service database + keycloak
  minio/objects.tar.age           every object in cve-poc-quarantine, cve-poc-artifacts, cve-reports
  rabbitmq/definitions.json.age
  config/env.age
  backup-info.txt                 time, platform commit, PostgreSQL version, encrypted=true
  SHA256SUMS
$BACKUP_DIR/LATEST                name of the newest complete set
```

A failed run leaves no partial set behind (`.incomplete-*` is removed). Sets older than
`BACKUP_RETENTION_DAYS` are deleted after a successful run.

### Schedule and off-host copies

Run backups hourly and verify each one. Example `/etc/cron.d/cve-platform` (adjust the paths and
user; the user needs Docker access):

```cron
15 * * * *  cve  cd /opt/cve-platform && infra/backup/backup.sh >> /var/log/cve-backup.log 2>&1
45 2 * * *  cve  cd /opt/cve-platform && BACKUP_AGE_IDENTITY_FILE=/run/secrets/backup.key infra/backup/verify.sh latest >> /var/log/cve-backup.log 2>&1
```

Verification needs the private key; run it on a separate restore host if the key must never touch
the platform host (recommended). Copy every set off the host after it is written, for example with
`rclone sync "$BACKUP_DIR" remote:cve-platform-backups --immutable` to object storage with object
lock. Monitor the cron jobs' exit status (the platform has no backup-freshness metric yet).

## Verifying a backup set

```bash
BACKUP_AGE_IDENTITY_FILE=~/platform-backup.key infra/backup/verify.sh latest
```

It checks every checksum, decrypts every file, parses each database dump completely with
`pg_restore --list`, lists the object archive and checks that the `.env` decrypts. It does not
modify any data. Only a restore proves a backup; run the drill below at least quarterly.

## Restoring

`restore.sh` is destructive: it replaces databases and bucket contents with the backup set. It
refuses to run without `--yes`, when checksums do not match, or while application services or
Keycloak are running.

### Restore on the existing host (data loss or corruption)

```bash
export COMPOSE_FILE=compose.yaml:compose.prod.yaml        # as for normal operation
docker compose --profile apps stop                         # services, web, Nginx
docker compose stop keycloak
docker compose up -d postgres minio                        # data stores only
BACKUP_AGE_IDENTITY_FILE=~/platform-backup.key infra/backup/restore.sh latest --yes
docker compose --profile apps --profile observability up -d --no-build
curl -fsS https://$PUBLIC_HOSTNAME/api/v1/health/live
```

Use `--only postgres` or `--only minio` to restore one store. For each database the script drops
and re-creates it with the same owner and grants as `infra/postgres/init` (no `PUBLIC` access, the
service role owns the `public` schema), then restores the dump **as the service role**, so object
ownership and cross-database isolation are exactly as after a migration.

After the restore, check `/api/v1/health/services` (all `ok`), the Grafana **Services** dashboard
and that a user can sign in.

### Rebuild on a new host (host loss)

1. Provision a host with Docker Engine and Compose ≥ 2.24, `age`, and `vm.max_map_count=262144`.
2. Check out the same platform version (`platform_commit` in `backup-info.txt`) and copy the backup
   set to the host.
3. Restore the configuration: `age -d -i platform-backup.key backups/<set>/config/env.age > .env`
   and `chmod 600 .env`. Adjust host-specific values (`PUBLIC_HOSTNAME`, `TLS_CERT_DIR`, …) if the
   host name changes; Keycloak redirect URIs then also need updating in the admin console.
4. Install TLS certificates in `TLS_CERT_DIR` and run `pnpm deploy:preflight`.
5. Start the data stores and provisioning: `docker compose up -d` (PostgreSQL initialises empty
   databases and roles from `.env`; MinIO buckets and users are provisioned).
6. Stop Keycloak (`docker compose stop keycloak`), then run
   `BACKUP_AGE_IDENTITY_FILE=… infra/backup/restore.sh backups/<set> --yes`.
7. Start everything: `docker compose --profile apps --profile observability up -d --no-build`.
8. Verify as above. RabbitMQ topology, Redis schedules and Grafana dashboards are re-created
   automatically.

### Event consistency after a restore

- Every service restores its own outbox: events written before the backup but not yet published
  are published again after the restore. Consumers deduplicate by event ID (inbox tables).
- Databases are dumped one after another, a few seconds apart. Events published between two dumps
  can be present in the consumer's database but missing from the producer's (or the reverse).
  Consumers treat events idempotently and services re-synchronise from the sources on their next
  scheduled run, but an artifact row can briefly reference an object copied later. After a
  restore, rescan artifacts whose scan status becomes `integrity-failure`
  (`POST /api/v1/download-artifacts/{id}/rescan`).
- Messages that were in RabbitMQ queues at the time of failure are lost when the RabbitMQ volume is
  lost. Their producers already marked them published, so they are not resent. Trigger a fresh
  synchronisation from **Data Sources** to rebuild derived projections if needed.

## Component failure playbook

| Failure                 | Impact                                                                | Action                                                                                                                                                            |
| ----------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| One service crashes     | Its API returns 502; others keep working                              | Compose restarts it (`restart: always`). `ServiceRestarting` alerts on crash loops; check its JSON logs                                                           |
| PostgreSQL down         | Every service not ready (`ServiceNotReady`)                           | `docker compose logs postgres`; restart. On corruption restore the latest set (`--only postgres`)                                                                 |
| RabbitMQ down           | Events queue in outboxes (`OutboxBacklog`)                            | Restart RabbitMQ; outboxes drain automatically. If its volume is lost, see "Event consistency"                                                                    |
| Redis down              | Background jobs stop; APIs that need it not ready                     | Restart Redis. If its volume is lost, restart the services so they re-create their job schedules                                                                  |
| MinIO down              | Download Service not ready; artifact downloads fail                   | Restart MinIO. On data loss restore with `--only minio`, then rescan affected artifacts                                                                           |
| Keycloak down           | Nobody can sign in; gateway not ready (`IdentityProviderUnavailable`) | Restart Keycloak; its data is in PostgreSQL                                                                                                                       |
| ClamAV down             | Download Service degraded; new artifacts stay `incomplete`            | Restart ClamAV, then rescan the incomplete artifacts (`POST /api/v1/download-artifacts/{id}/rescan`). Nothing can be released while a required scanner is missing |
| TLS certificate expired | Browsers refuse the site                                              | Renew (docs/deployment.md), `docker compose restart nginx`. `pnpm deploy:preflight` warns 21 days ahead                                                           |
| Secret leaked           | Depends on the secret                                                 | Rotate it ([Rotating secrets](infrastructure.md#rotating-secrets)) and take a new backup; old sets still contain the old `.env`                                   |
| Host lost               | Full outage                                                           | "Rebuild on a new host" above                                                                                                                                     |

## Restore drill

Run a full restore on a scratch host or a disposable Compose project at least once a quarter and
after every PostgreSQL major upgrade. Record the duration as your measured RTO.

The drill performed while building this tooling (Compose project with PostgreSQL 17 and MinIO,
CVE and Download Service schemas migrated, encrypted set):

1. backup, `verify.sh latest` (75 and 67 archive entries for the CVE and Download databases);
2. damage: a row changed and another inserted, a CVE Service table dropped, one object deleted and
   another created;
3. `restore.sh latest` without `--yes` refused; with `--yes` restored 10 databases and 3 buckets;
4. result: schema dumps byte-identical to before the backup, the original row back and the extra
   one gone, every table owned by its service role, `cve_service` still unable to connect to
   `download_service`, the deleted object back and the later object removed.
