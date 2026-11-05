-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "owner_type" AS ENUM ('user', 'organization', 'bot', 'unknown');

-- CreateEnum
CREATE TYPE "repository_status" AS ENUM ('active', 'unavailable');

-- CreateEnum
CREATE TYPE "association_review_status" AS ENUM ('candidate', 'confirmed', 'rejected');

-- CreateEnum
CREATE TYPE "association_origin" AS ENUM ('discovered', 'manual');

-- CreateEnum
CREATE TYPE "confidence_level" AS ENUM ('high', 'medium', 'low');

-- CreateEnum
CREATE TYPE "verification_status" AS ENUM ('unverified', 'in-review', 'verified', 'rejected', 'malicious');

-- CreateEnum
CREATE TYPE "duplicate_kind" AS ENUM ('exact', 'near');

-- CreateEnum
CREATE TYPE "reference_kind" AS ENUM ('github-repository', 'github-gist', 'exploit-db', 'packet-storm', 'other');

-- CreateEnum
CREATE TYPE "discovery_run_status" AS ENUM ('running', 'succeeded', 'failed');

-- CreateTable
CREATE TABLE "repository_owners" (
    "id" UUID NOT NULL,
    "source" VARCHAR(32) NOT NULL,
    "external_id" VARCHAR(64) NOT NULL,
    "login" VARCHAR(64) NOT NULL,
    "login_key" VARCHAR(64) NOT NULL,
    "type" "owner_type" NOT NULL,
    "url" VARCHAR(300) NOT NULL,
    "first_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "repository_owners_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "poc_repositories" (
    "id" UUID NOT NULL,
    "source" VARCHAR(32) NOT NULL,
    "external_id" VARCHAR(64) NOT NULL,
    "owner_id" UUID NOT NULL,
    "name" VARCHAR(100) NOT NULL,
    "full_name" VARCHAR(200) NOT NULL,
    "full_name_key" VARCHAR(200) NOT NULL,
    "url" VARCHAR(300) NOT NULL,
    "description" VARCHAR(1000),
    "topics" TEXT[],
    "language" VARCHAR(64),
    "stars" INTEGER NOT NULL DEFAULT 0,
    "forks" INTEGER NOT NULL DEFAULT 0,
    "is_fork" BOOLEAN NOT NULL,
    "parent_full_name" VARCHAR(200),
    "is_archived" BOOLEAN NOT NULL,
    "default_branch" VARCHAR(255),
    "size_kb" INTEGER NOT NULL DEFAULT 0,
    "status" "repository_status" NOT NULL DEFAULT 'active',
    "source_created_at" TIMESTAMPTZ(3),
    "source_pushed_at" TIMESTAMPTZ(3),
    "metadata_hash" CHAR(64) NOT NULL,
    "discovered_by" VARCHAR(32) NOT NULL,
    "latest_commit_sha" CHAR(40),
    "latest_artifact_id" UUID,
    "is_empty" BOOLEAN NOT NULL DEFAULT false,
    "max_confidence" DECIMAL(4,3),
    "inspection_due_at" TIMESTAMPTZ(3),
    "last_inspected_at" TIMESTAMPTZ(3),
    "inspected_pushed_at" TIMESTAMPTZ(3),
    "first_discovered_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "poc_repositories_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "repository_commits" (
    "id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "sha" CHAR(40) NOT NULL,
    "tree_sha" CHAR(40) NOT NULL,
    "committed_at" TIMESTAMPTZ(3),
    "observed_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "artifact_id" UUID,

    CONSTRAINT "repository_commits_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "poc_artifacts" (
    "id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "commit_sha" CHAR(40) NOT NULL,
    "tree_sha" CHAR(40) NOT NULL,
    "fingerprint" CHAR(64) NOT NULL,
    "file_count" INTEGER NOT NULL,
    "total_bytes" BIGINT NOT NULL,
    "listing_truncated" BOOLEAN NOT NULL,
    "has_source_code" BOOLEAN NOT NULL,
    "risk_indicators" TEXT[],
    "duplicate_kind" "duplicate_kind",
    "duplicate_of_id" UUID,
    "similarity" DECIMAL(4,3),
    "verification_status" "verification_status" NOT NULL DEFAULT 'unverified',
    "verification_updated_at" TIMESTAMPTZ(3),
    "verification_updated_by" VARCHAR(255),
    "discovered_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "version" INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT "poc_artifacts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "artifact_files" (
    "id" UUID NOT NULL,
    "artifact_id" UUID NOT NULL,
    "path" VARCHAR(1024) NOT NULL,
    "blob_sha" CHAR(40) NOT NULL,
    "size_bytes" INTEGER,
    "category" VARCHAR(16) NOT NULL,
    "significant" BOOLEAN NOT NULL,

    CONSTRAINT "artifact_files_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "artifact_verification_events" (
    "id" UUID NOT NULL,
    "artifact_id" UUID NOT NULL,
    "from_status" "verification_status" NOT NULL,
    "to_status" "verification_status" NOT NULL,
    "reason" VARCHAR(2000) NOT NULL,
    "actor_id" VARCHAR(255) NOT NULL,
    "actor_username" VARCHAR(255),
    "correlation_id" VARCHAR(128),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "artifact_verification_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "poc_cve_associations" (
    "id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "cve_id" VARCHAR(32) NOT NULL,
    "confidence" DECIMAL(4,3) NOT NULL,
    "confidence_level" "confidence_level" NOT NULL,
    "signals" JSONB NOT NULL,
    "penalties" JSONB NOT NULL,
    "scoring_version" INTEGER NOT NULL,
    "origin" "association_origin" NOT NULL,
    "search_matched_at" TIMESTAMPTZ(3),
    "manual" BOOLEAN NOT NULL DEFAULT false,
    "review_status" "association_review_status" NOT NULL DEFAULT 'candidate',
    "reviewed_by" VARCHAR(255),
    "reviewed_at" TIMESTAMPTZ(3),
    "review_note" VARCHAR(2000),
    "first_discovered_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_evaluated_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "version" INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT "poc_cve_associations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "poc_references" (
    "id" UUID NOT NULL,
    "cve_id" VARCHAR(32) NOT NULL,
    "url" VARCHAR(2048) NOT NULL,
    "url_hash" CHAR(64) NOT NULL,
    "kind" "reference_kind" NOT NULL,
    "source" VARCHAR(128) NOT NULL,
    "tags" TEXT[],
    "repository_key" VARCHAR(200),
    "repository_id" UUID,
    "resolve_queued_at" TIMESTAMPTZ(3),
    "removed_at" TIMESTAMPTZ(3),
    "first_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "poc_references_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "observation_cursors" (
    "id" UUID NOT NULL,
    "source" VARCHAR(64) NOT NULL,
    "source_record_id" VARCHAR(128) NOT NULL,
    "cve_id" VARCHAR(32) NOT NULL,
    "revision" INTEGER NOT NULL,
    "applied_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "observation_cursors_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "tracked_cves" (
    "cve_id" VARCHAR(32) NOT NULL,
    "record_id" UUID NOT NULL,
    "record_version" INTEGER NOT NULL,
    "state" VARCHAR(16) NOT NULL,
    "in_kev" BOOLEAN NOT NULL,
    "epss_score" DECIMAL(6,5),
    "published_at" TIMESTAMPTZ(3),
    "deleted_at" TIMESTAMPTZ(3),
    "event_occurred_at" TIMESTAMPTZ(3) NOT NULL,
    "next_scan_at" TIMESTAMPTZ(3),
    "last_scanned_at" TIMESTAMPTZ(3),
    "scan_count" INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT "tracked_cves_pkey" PRIMARY KEY ("cve_id")
);

-- CreateTable
CREATE TABLE "discovery_runs" (
    "id" UUID NOT NULL,
    "connector" VARCHAR(32) NOT NULL,
    "mode" VARCHAR(16) NOT NULL,
    "trigger" VARCHAR(16) NOT NULL,
    "status" "discovery_run_status" NOT NULL DEFAULT 'running',
    "cve_id" VARCHAR(32),
    "repository_id" UUID,
    "job_id" VARCHAR(128),
    "attempt" INTEGER NOT NULL DEFAULT 1,
    "requested_by" VARCHAR(255),
    "correlation_id" VARCHAR(128),
    "started_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finished_at" TIMESTAMPTZ(3),
    "stats" JSONB NOT NULL,
    "error" VARCHAR(2000),

    CONSTRAINT "discovery_runs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "connector_states" (
    "connector" VARCHAR(32) NOT NULL,
    "cursor" JSONB NOT NULL,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "connector_states_pkey" PRIMARY KEY ("connector")
);

-- CreateTable
CREATE TABLE "processed_events" (
    "id" UUID NOT NULL,
    "consumer" VARCHAR(64) NOT NULL,
    "event_id" UUID NOT NULL,
    "processed_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "processed_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "outbox_events" (
    "id" UUID NOT NULL,
    "event_id" UUID NOT NULL,
    "event_type" VARCHAR(128) NOT NULL,
    "envelope" JSONB NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "last_error" VARCHAR(2000),
    "next_attempt_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "locked_until" TIMESTAMPTZ(3),
    "published_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "outbox_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "repository_owners_login_key_idx" ON "repository_owners"("login_key");

-- CreateIndex
CREATE UNIQUE INDEX "repository_owners_source_external_id_key" ON "repository_owners"("source", "external_id");

-- CreateIndex
CREATE INDEX "poc_repositories_full_name_key_idx" ON "poc_repositories"("full_name_key");

-- CreateIndex
CREATE INDEX "poc_repositories_owner_id_idx" ON "poc_repositories"("owner_id");

-- CreateIndex
CREATE INDEX "poc_repositories_inspection_due_at_idx" ON "poc_repositories"("inspection_due_at");

-- CreateIndex
CREATE INDEX "poc_repositories_first_discovered_at_idx" ON "poc_repositories"("first_discovered_at");

-- CreateIndex
CREATE UNIQUE INDEX "poc_repositories_source_external_id_key" ON "poc_repositories"("source", "external_id");

-- CreateIndex
CREATE INDEX "repository_commits_repository_id_observed_at_idx" ON "repository_commits"("repository_id", "observed_at");

-- CreateIndex
CREATE UNIQUE INDEX "repository_commits_repository_id_sha_key" ON "repository_commits"("repository_id", "sha");

-- CreateIndex
CREATE INDEX "poc_artifacts_tree_sha_idx" ON "poc_artifacts"("tree_sha");

-- CreateIndex
CREATE INDEX "poc_artifacts_fingerprint_idx" ON "poc_artifacts"("fingerprint");

-- CreateIndex
CREATE INDEX "poc_artifacts_verification_status_idx" ON "poc_artifacts"("verification_status");

-- CreateIndex
CREATE INDEX "poc_artifacts_discovered_at_idx" ON "poc_artifacts"("discovered_at");

-- CreateIndex
CREATE UNIQUE INDEX "poc_artifacts_repository_id_tree_sha_key" ON "poc_artifacts"("repository_id", "tree_sha");

-- CreateIndex
CREATE INDEX "artifact_files_artifact_id_idx" ON "artifact_files"("artifact_id");

-- CreateIndex
CREATE INDEX "artifact_files_blob_sha_idx" ON "artifact_files"("blob_sha");

-- CreateIndex
CREATE INDEX "artifact_verification_events_artifact_id_created_at_idx" ON "artifact_verification_events"("artifact_id", "created_at");

-- CreateIndex
CREATE INDEX "poc_cve_associations_cve_id_confidence_idx" ON "poc_cve_associations"("cve_id", "confidence");

-- CreateIndex
CREATE INDEX "poc_cve_associations_review_status_idx" ON "poc_cve_associations"("review_status");

-- CreateIndex
CREATE UNIQUE INDEX "poc_cve_associations_repository_id_cve_id_key" ON "poc_cve_associations"("repository_id", "cve_id");

-- CreateIndex
CREATE INDEX "poc_references_repository_key_idx" ON "poc_references"("repository_key");

-- CreateIndex
CREATE INDEX "poc_references_repository_id_idx" ON "poc_references"("repository_id");

-- CreateIndex
CREATE UNIQUE INDEX "poc_references_cve_id_source_url_hash_key" ON "poc_references"("cve_id", "source", "url_hash");

-- CreateIndex
CREATE UNIQUE INDEX "observation_cursors_source_source_record_id_key" ON "observation_cursors"("source", "source_record_id");

-- CreateIndex
CREATE INDEX "tracked_cves_next_scan_at_idx" ON "tracked_cves"("next_scan_at");

-- CreateIndex
CREATE INDEX "discovery_runs_started_at_idx" ON "discovery_runs"("started_at");

-- CreateIndex
CREATE INDEX "discovery_runs_connector_mode_started_at_idx" ON "discovery_runs"("connector", "mode", "started_at");

-- CreateIndex
CREATE INDEX "discovery_runs_status_started_at_idx" ON "discovery_runs"("status", "started_at");

-- CreateIndex
CREATE INDEX "discovery_runs_cve_id_idx" ON "discovery_runs"("cve_id");

-- CreateIndex
CREATE INDEX "processed_events_processed_at_idx" ON "processed_events"("processed_at");

-- CreateIndex
CREATE UNIQUE INDEX "processed_events_consumer_event_id_key" ON "processed_events"("consumer", "event_id");

-- CreateIndex
CREATE UNIQUE INDEX "outbox_events_event_id_key" ON "outbox_events"("event_id");

-- CreateIndex
CREATE INDEX "outbox_events_published_at_next_attempt_at_idx" ON "outbox_events"("published_at", "next_attempt_at");

-- AddForeignKey
ALTER TABLE "poc_repositories" ADD CONSTRAINT "poc_repositories_owner_id_fkey" FOREIGN KEY ("owner_id") REFERENCES "repository_owners"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "repository_commits" ADD CONSTRAINT "repository_commits_repository_id_fkey" FOREIGN KEY ("repository_id") REFERENCES "poc_repositories"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "repository_commits" ADD CONSTRAINT "repository_commits_artifact_id_fkey" FOREIGN KEY ("artifact_id") REFERENCES "poc_artifacts"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "poc_artifacts" ADD CONSTRAINT "poc_artifacts_repository_id_fkey" FOREIGN KEY ("repository_id") REFERENCES "poc_repositories"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "poc_artifacts" ADD CONSTRAINT "poc_artifacts_duplicate_of_id_fkey" FOREIGN KEY ("duplicate_of_id") REFERENCES "poc_artifacts"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "artifact_files" ADD CONSTRAINT "artifact_files_artifact_id_fkey" FOREIGN KEY ("artifact_id") REFERENCES "poc_artifacts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "artifact_verification_events" ADD CONSTRAINT "artifact_verification_events_artifact_id_fkey" FOREIGN KEY ("artifact_id") REFERENCES "poc_artifacts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "poc_cve_associations" ADD CONSTRAINT "poc_cve_associations_repository_id_fkey" FOREIGN KEY ("repository_id") REFERENCES "poc_repositories"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "poc_references" ADD CONSTRAINT "poc_references_repository_id_fkey" FOREIGN KEY ("repository_id") REFERENCES "poc_repositories"("id") ON DELETE SET NULL ON UPDATE CASCADE;


-- ---------------------------------------------------------------------------- hand-written
-- Invariants Prisma cannot express. Keep them in later migrations.
ALTER TABLE "poc_repositories"
  ADD CONSTRAINT "poc_repositories_full_name_key_lower" CHECK ("full_name_key" = lower("full_name")),
  ADD CONSTRAINT "poc_repositories_url_github" CHECK ("url" LIKE 'https://github.com/%'),
  ADD CONSTRAINT "poc_repositories_max_confidence_range" CHECK ("max_confidence" BETWEEN 0 AND 1),
  ADD CONSTRAINT "poc_repositories_counts" CHECK ("stars" >= 0 AND "forks" >= 0 AND "size_kb" >= 0);
ALTER TABLE "repository_commits"
  ADD CONSTRAINT "repository_commits_sha_format" CHECK ("sha" ~ '^[0-9a-f]{40}$' AND "tree_sha" ~ '^[0-9a-f]{40}$');
ALTER TABLE "poc_artifacts"
  ADD CONSTRAINT "poc_artifacts_sha_format" CHECK ("commit_sha" ~ '^[0-9a-f]{40}$' AND "tree_sha" ~ '^[0-9a-f]{40}$'),
  ADD CONSTRAINT "poc_artifacts_fingerprint_format" CHECK ("fingerprint" ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT "poc_artifacts_similarity_range" CHECK ("similarity" BETWEEN 0 AND 1),
  ADD CONSTRAINT "poc_artifacts_duplicate_consistent" CHECK (("duplicate_kind" IS NULL) = ("similarity" IS NULL)),
  ADD CONSTRAINT "poc_artifacts_not_own_duplicate" CHECK ("duplicate_of_id" IS DISTINCT FROM "id"),
  ADD CONSTRAINT "poc_artifacts_counts" CHECK ("file_count" >= 0 AND "total_bytes" >= 0);
ALTER TABLE "poc_cve_associations"
  ADD CONSTRAINT "poc_cve_associations_cve_id_format" CHECK ("cve_id" ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
  ADD CONSTRAINT "poc_cve_associations_confidence_range" CHECK ("confidence" BETWEEN 0 AND 1);
ALTER TABLE "poc_references"
  ADD CONSTRAINT "poc_references_cve_id_format" CHECK ("cve_id" ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
  ADD CONSTRAINT "poc_references_url_hash_format" CHECK ("url_hash" ~ '^[0-9a-f]{64}$');
ALTER TABLE "tracked_cves"
  ADD CONSTRAINT "tracked_cves_cve_id_format" CHECK ("cve_id" ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
  ADD CONSTRAINT "tracked_cves_epss_score_range" CHECK ("epss_score" BETWEEN 0 AND 1);
ALTER TABLE "observation_cursors"
  ADD CONSTRAINT "observation_cursors_revision_positive" CHECK ("revision" >= 1);

-- Verification history is append-only: decisions are never edited or removed.
CREATE FUNCTION "reject_verification_event_change"() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'artifact_verification_events is append-only';
END;
$$;
CREATE TRIGGER "artifact_verification_events_append_only"
  BEFORE UPDATE ON "artifact_verification_events"
  FOR EACH ROW EXECUTE FUNCTION "reject_verification_event_change"();
