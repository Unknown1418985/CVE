-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "download_request_status" AS ENUM ('pending', 'downloading', 'stored', 'duplicate', 'failed', 'rejected', 'cancelled');

-- CreateEnum
CREATE TYPE "download_attempt_outcome" AS ENUM ('succeeded', 'failed', 'rejected');

-- CreateEnum
CREATE TYPE "artifact_lifecycle_status" AS ENUM ('quarantined', 'released', 'rejected');

-- CreateEnum
CREATE TYPE "artifact_scan_status" AS ENUM ('pending', 'scanning', 'clean', 'suspicious', 'malicious', 'incomplete', 'integrity-failure');

-- CreateEnum
CREATE TYPE "scan_verdict" AS ENUM ('clean', 'suspicious', 'malicious', 'error', 'not-configured');

-- CreateEnum
CREATE TYPE "verification_status" AS ENUM ('unverified', 'in-review', 'verified', 'rejected', 'malicious');

-- CreateTable
CREATE TABLE "download_requests" (
    "id" UUID NOT NULL,
    "source" VARCHAR(32) NOT NULL,
    "source_url" VARCHAR(2048) NOT NULL,
    "url_hash" CHAR(64) NOT NULL,
    "trigger" VARCHAR(16) NOT NULL,
    "status" "download_request_status" NOT NULL DEFAULT 'pending',
    "poc_artifact_id" UUID,
    "poc_repository_id" UUID,
    "source_repository" VARCHAR(200),
    "commit_sha" CHAR(40),
    "cve_ids" TEXT[],
    "priority" INTEGER NOT NULL DEFAULT 5,
    "scheduled_for" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "max_attempts" INTEGER NOT NULL,
    "queued_at" TIMESTAMPTZ(3),
    "job_id" VARCHAR(128),
    "lease_until" TIMESTAMPTZ(3),
    "error_code" VARCHAR(64),
    "error" VARCHAR(2000),
    "artifact_id" UUID,
    "requested_by" VARCHAR(255),
    "reason" VARCHAR(2000),
    "correlation_id" VARCHAR(128),
    "discovered_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "finished_at" TIMESTAMPTZ(3),
    "version" INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT "download_requests_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "download_attempts" (
    "id" UUID NOT NULL,
    "request_id" UUID NOT NULL,
    "attempt" INTEGER NOT NULL,
    "job_id" VARCHAR(128),
    "outcome" "download_attempt_outcome",
    "error_code" VARCHAR(64),
    "error" VARCHAR(2000),
    "retryable" BOOLEAN,
    "http_status" INTEGER,
    "hops" JSONB NOT NULL,
    "final_url" VARCHAR(2048),
    "declared_content_type" VARCHAR(255),
    "declared_length" BIGINT,
    "bytes_received" BIGINT NOT NULL DEFAULT 0,
    "sha256" CHAR(64),
    "started_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finished_at" TIMESTAMPTZ(3),
    "duration_ms" INTEGER,

    CONSTRAINT "download_attempts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "stored_artifacts" (
    "id" UUID NOT NULL,
    "sha256" CHAR(64) NOT NULL,
    "size_bytes" BIGINT NOT NULL,
    "mime_type" VARCHAR(128) NOT NULL,
    "detected_type" VARCHAR(32) NOT NULL,
    "declared_content_type" VARCHAR(255),
    "original_filename" VARCHAR(255),
    "storage_bucket" VARCHAR(63) NOT NULL,
    "storage_key" VARCHAR(255) NOT NULL,
    "released_key" VARCHAR(255),
    "source" VARCHAR(32) NOT NULL,
    "source_url" VARCHAR(2048) NOT NULL,
    "source_repository" VARCHAR(200),
    "cve_ids" TEXT[],
    "risk_indicators" TEXT[],
    "lifecycle_status" "artifact_lifecycle_status" NOT NULL DEFAULT 'quarantined',
    "scan_status" "artifact_scan_status" NOT NULL DEFAULT 'pending',
    "verification_status" "verification_status" NOT NULL DEFAULT 'unverified',
    "scan_queued_at" TIMESTAMPTZ(3),
    "last_scanned_at" TIMESTAMPTZ(3),
    "discovered_at" TIMESTAMPTZ(3) NOT NULL,
    "downloaded_at" TIMESTAMPTZ(3) NOT NULL,
    "released_at" TIMESTAMPTZ(3),
    "released_by" VARCHAR(255),
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "stored_artifacts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "artifact_sources" (
    "id" UUID NOT NULL,
    "artifact_id" UUID NOT NULL,
    "request_id" UUID NOT NULL,
    "source" VARCHAR(32) NOT NULL,
    "source_url" VARCHAR(2048) NOT NULL,
    "final_url" VARCHAR(2048),
    "source_repository" VARCHAR(200),
    "poc_artifact_id" UUID,
    "commit_sha" CHAR(40),
    "cve_ids" TEXT[],
    "discovered_at" TIMESTAMPTZ(3) NOT NULL,
    "downloaded_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "artifact_sources_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_results" (
    "id" UUID NOT NULL,
    "artifact_id" UUID NOT NULL,
    "scan_run_id" UUID NOT NULL,
    "scanner" VARCHAR(32) NOT NULL,
    "verdict" "scan_verdict" NOT NULL,
    "findings" JSONB NOT NULL,
    "engine_version" VARCHAR(255),
    "signature_version" VARCHAR(255),
    "error" VARCHAR(2000),
    "started_at" TIMESTAMPTZ(3) NOT NULL,
    "finished_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "scan_results_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "artifact_lifecycle_events" (
    "id" UUID NOT NULL,
    "artifact_id" UUID NOT NULL,
    "from_status" "artifact_lifecycle_status",
    "to_status" "artifact_lifecycle_status" NOT NULL,
    "reason" VARCHAR(2000) NOT NULL,
    "actor_id" VARCHAR(255) NOT NULL,
    "actor_username" VARCHAR(255),
    "correlation_id" VARCHAR(128),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "artifact_lifecycle_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "poc_artifact_states" (
    "poc_artifact_id" UUID NOT NULL,
    "repository_id" UUID NOT NULL,
    "repository_full_name" VARCHAR(200),
    "commit_sha" CHAR(40) NOT NULL,
    "cve_ids" TEXT[],
    "total_bytes" BIGINT,
    "verification_status" "verification_status" NOT NULL,
    "verification_version" INTEGER NOT NULL DEFAULT 0,
    "event_occurred_at" TIMESTAMPTZ(3) NOT NULL,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "poc_artifact_states_pkey" PRIMARY KEY ("poc_artifact_id")
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
CREATE INDEX "download_requests_status_scheduled_for_idx" ON "download_requests"("status", "scheduled_for");

-- CreateIndex
CREATE INDEX "download_requests_poc_artifact_id_idx" ON "download_requests"("poc_artifact_id");

-- CreateIndex
CREATE INDEX "download_requests_artifact_id_idx" ON "download_requests"("artifact_id");

-- CreateIndex
CREATE INDEX "download_requests_created_at_idx" ON "download_requests"("created_at");

-- CreateIndex
CREATE UNIQUE INDEX "download_requests_source_url_hash_key" ON "download_requests"("source", "url_hash");

-- CreateIndex
CREATE INDEX "download_attempts_started_at_idx" ON "download_attempts"("started_at");

-- CreateIndex
CREATE UNIQUE INDEX "download_attempts_request_id_attempt_key" ON "download_attempts"("request_id", "attempt");

-- CreateIndex
CREATE UNIQUE INDEX "stored_artifacts_sha256_key" ON "stored_artifacts"("sha256");

-- CreateIndex
CREATE UNIQUE INDEX "stored_artifacts_storage_key_key" ON "stored_artifacts"("storage_key");

-- CreateIndex
CREATE INDEX "stored_artifacts_lifecycle_status_downloaded_at_idx" ON "stored_artifacts"("lifecycle_status", "downloaded_at");

-- CreateIndex
CREATE INDEX "stored_artifacts_scan_status_idx" ON "stored_artifacts"("scan_status");

-- CreateIndex
CREATE INDEX "stored_artifacts_downloaded_at_idx" ON "stored_artifacts"("downloaded_at");

-- CreateIndex
CREATE UNIQUE INDEX "artifact_sources_request_id_key" ON "artifact_sources"("request_id");

-- CreateIndex
CREATE INDEX "artifact_sources_artifact_id_idx" ON "artifact_sources"("artifact_id");

-- CreateIndex
CREATE INDEX "artifact_sources_poc_artifact_id_idx" ON "artifact_sources"("poc_artifact_id");

-- CreateIndex
CREATE INDEX "scan_results_artifact_id_finished_at_idx" ON "scan_results"("artifact_id", "finished_at");

-- CreateIndex
CREATE INDEX "scan_results_scan_run_id_idx" ON "scan_results"("scan_run_id");

-- CreateIndex
CREATE INDEX "artifact_lifecycle_events_artifact_id_created_at_idx" ON "artifact_lifecycle_events"("artifact_id", "created_at");

-- CreateIndex
CREATE INDEX "processed_events_processed_at_idx" ON "processed_events"("processed_at");

-- CreateIndex
CREATE UNIQUE INDEX "processed_events_consumer_event_id_key" ON "processed_events"("consumer", "event_id");

-- CreateIndex
CREATE UNIQUE INDEX "outbox_events_event_id_key" ON "outbox_events"("event_id");

-- CreateIndex
CREATE INDEX "outbox_events_published_at_next_attempt_at_idx" ON "outbox_events"("published_at", "next_attempt_at");

-- AddForeignKey
ALTER TABLE "download_requests" ADD CONSTRAINT "download_requests_artifact_id_fkey" FOREIGN KEY ("artifact_id") REFERENCES "stored_artifacts"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "download_attempts" ADD CONSTRAINT "download_attempts_request_id_fkey" FOREIGN KEY ("request_id") REFERENCES "download_requests"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "artifact_sources" ADD CONSTRAINT "artifact_sources_artifact_id_fkey" FOREIGN KEY ("artifact_id") REFERENCES "stored_artifacts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "artifact_sources" ADD CONSTRAINT "artifact_sources_request_id_fkey" FOREIGN KEY ("request_id") REFERENCES "download_requests"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_artifact_id_fkey" FOREIGN KEY ("artifact_id") REFERENCES "stored_artifacts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "artifact_lifecycle_events" ADD CONSTRAINT "artifact_lifecycle_events_artifact_id_fkey" FOREIGN KEY ("artifact_id") REFERENCES "stored_artifacts"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- ---------------------------------------------------------------------------- hand-written
-- Integrity rules the Prisma schema cannot express.
ALTER TABLE "download_requests"
  ADD CONSTRAINT "download_requests_url_https" CHECK ("source_url" LIKE 'https://%'),
  ADD CONSTRAINT "download_requests_url_hash_format" CHECK ("url_hash" ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT "download_requests_commit_sha_format" CHECK ("commit_sha" IS NULL OR "commit_sha" ~ '^[0-9a-f]{40}$'),
  ADD CONSTRAINT "download_requests_attempts" CHECK ("attempts" >= 0 AND "max_attempts" >= 1),
  ADD CONSTRAINT "download_requests_priority_range" CHECK ("priority" BETWEEN 1 AND 10),
  ADD CONSTRAINT "download_requests_cve_ids_format" CHECK (array_to_string("cve_ids", ',') ~ '^(CVE-[0-9]{4}-[0-9]{4,19}(,|$))*$');
ALTER TABLE "download_attempts"
  ADD CONSTRAINT "download_attempts_sha256_format" CHECK ("sha256" IS NULL OR "sha256" ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT "download_attempts_bytes" CHECK ("bytes_received" >= 0);
ALTER TABLE "stored_artifacts"
  ADD CONSTRAINT "stored_artifacts_sha256_format" CHECK ("sha256" ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT "stored_artifacts_size" CHECK ("size_bytes" >= 0),
  -- Object keys are generated by the service: a fixed prefix and the artifact's UUID only.
  ADD CONSTRAINT "stored_artifacts_storage_key_format"
    CHECK ("storage_key" ~ '^quarantine/[0-9]{4}/[0-9]{2}/[0-9a-f-]{36}$'),
  ADD CONSTRAINT "stored_artifacts_released_key_format"
    CHECK ("released_key" IS NULL OR "released_key" ~ '^released/[0-9a-f-]{36}$'),
  -- A released artifact has a released copy and a clean scan; nothing else is ever released.
  ADD CONSTRAINT "stored_artifacts_release_requires_clean_scan"
    CHECK ("lifecycle_status" <> 'released' OR ("scan_status" = 'clean' AND "released_key" IS NOT NULL)),
  ADD CONSTRAINT "stored_artifacts_release_requires_trusted_verification"
    CHECK ("lifecycle_status" <> 'released' OR "verification_status" NOT IN ('malicious', 'rejected'));

-- Lifecycle history is append-only: decisions are never edited.
CREATE FUNCTION "reject_lifecycle_event_change"() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'artifact_lifecycle_events is append-only';
END;
$$;
CREATE TRIGGER "artifact_lifecycle_events_append_only"
  BEFORE UPDATE ON "artifact_lifecycle_events"
  FOR EACH ROW EXECUTE FUNCTION "reject_lifecycle_event_change"();
