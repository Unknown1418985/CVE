-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "sync_run_status" AS ENUM ('running', 'succeeded', 'failed', 'abandoned');

-- CreateEnum
CREATE TYPE "sync_trigger" AS ENUM ('scheduled', 'manual', 'recovery');

-- CreateTable
CREATE TABLE "source_sync_states" (
    "source" VARCHAR(32) NOT NULL,
    "cursor" JSONB,
    "last_run_at" TIMESTAMPTZ(3),
    "last_run_status" "sync_run_status",
    "last_success_at" TIMESTAMPTZ(3),
    "consecutive_failures" INTEGER NOT NULL DEFAULT 0,
    "lease_owner" VARCHAR(200),
    "lease_expires_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "source_sync_states_pkey" PRIMARY KEY ("source")
);

-- CreateTable
CREATE TABLE "sync_runs" (
    "id" UUID NOT NULL,
    "source" VARCHAR(32) NOT NULL,
    "trigger" "sync_trigger" NOT NULL,
    "status" "sync_run_status" NOT NULL DEFAULT 'running',
    "job_id" VARCHAR(160),
    "attempt" INTEGER NOT NULL DEFAULT 1,
    "requested_by" VARCHAR(200),
    "resumed_from_run_id" UUID,
    "started_at" TIMESTAMPTZ(3) NOT NULL,
    "heartbeat_at" TIMESTAMPTZ(3) NOT NULL,
    "finished_at" TIMESTAMPTZ(3),
    "cursor_before" JSONB,
    "cursor_after" JSONB,
    "checkpoint" JSONB,
    "stats" JSONB NOT NULL,
    "error" VARCHAR(2000),
    "issue_count" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sync_runs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sync_run_issues" (
    "id" UUID NOT NULL,
    "run_id" UUID NOT NULL,
    "source_record_id" VARCHAR(128),
    "message" VARCHAR(2000) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sync_run_issues_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "source_records" (
    "id" UUID NOT NULL,
    "source" VARCHAR(32) NOT NULL,
    "external_id" VARCHAR(128) NOT NULL,
    "cve_id" VARCHAR(32),
    "source_url" VARCHAR(2048) NOT NULL,
    "content_hash" CHAR(64) NOT NULL,
    "revision" INTEGER NOT NULL DEFAULT 1,
    "content" JSONB NOT NULL,
    "raw" JSONB,
    "source_modified_at" TIMESTAMPTZ(3),
    "first_seen_at" TIMESTAMPTZ(3) NOT NULL,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL,
    "last_changed_at" TIMESTAMPTZ(3) NOT NULL,
    "removed_at" TIMESTAMPTZ(3),
    "last_run_id" UUID,

    CONSTRAINT "source_records_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "source_record_revisions" (
    "id" UUID NOT NULL,
    "record_id" UUID NOT NULL,
    "revision" INTEGER NOT NULL,
    "content_hash" CHAR(64) NOT NULL,
    "content" JSONB NOT NULL,
    "source_modified_at" TIMESTAMPTZ(3),
    "removed" BOOLEAN NOT NULL DEFAULT false,
    "observed_at" TIMESTAMPTZ(3) NOT NULL,
    "run_id" UUID NOT NULL,

    CONSTRAINT "source_record_revisions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "epss_scores" (
    "cve_id" VARCHAR(32) NOT NULL,
    "score_date" DATE NOT NULL,
    "score" DECIMAL(10,9) NOT NULL,
    "percentile" DECIMAL(10,9) NOT NULL,
    "model_version" VARCHAR(32),
    "observed_at" TIMESTAMPTZ(3) NOT NULL,
    "run_id" UUID NOT NULL,

    CONSTRAINT "epss_scores_pkey" PRIMARY KEY ("cve_id","score_date")
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
CREATE UNIQUE INDEX "sync_runs_resumed_from_run_id_key" ON "sync_runs"("resumed_from_run_id");

-- CreateIndex
CREATE INDEX "sync_runs_source_started_at_idx" ON "sync_runs"("source", "started_at" DESC);

-- CreateIndex
CREATE INDEX "sync_runs_status_heartbeat_at_idx" ON "sync_runs"("status", "heartbeat_at");

-- CreateIndex
CREATE INDEX "sync_runs_started_at_idx" ON "sync_runs"("started_at" DESC);

-- CreateIndex
CREATE INDEX "sync_run_issues_run_id_created_at_idx" ON "sync_run_issues"("run_id", "created_at");

-- CreateIndex
CREATE INDEX "source_records_cve_id_idx" ON "source_records"("cve_id");

-- CreateIndex
CREATE INDEX "source_records_source_last_changed_at_idx" ON "source_records"("source", "last_changed_at");

-- CreateIndex
CREATE UNIQUE INDEX "source_records_source_external_id_key" ON "source_records"("source", "external_id");

-- CreateIndex
CREATE UNIQUE INDEX "source_record_revisions_record_id_revision_key" ON "source_record_revisions"("record_id", "revision");

-- CreateIndex
CREATE INDEX "epss_scores_score_date_idx" ON "epss_scores"("score_date");

-- CreateIndex
CREATE UNIQUE INDEX "outbox_events_event_id_key" ON "outbox_events"("event_id");

-- CreateIndex
CREATE INDEX "outbox_events_published_at_next_attempt_at_idx" ON "outbox_events"("published_at", "next_attempt_at");

-- AddForeignKey
ALTER TABLE "sync_runs" ADD CONSTRAINT "sync_runs_resumed_from_run_id_fkey" FOREIGN KEY ("resumed_from_run_id") REFERENCES "sync_runs"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sync_run_issues" ADD CONSTRAINT "sync_run_issues_run_id_fkey" FOREIGN KEY ("run_id") REFERENCES "sync_runs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "source_record_revisions" ADD CONSTRAINT "source_record_revisions_record_id_fkey" FOREIGN KEY ("record_id") REFERENCES "source_records"("id") ON DELETE CASCADE ON UPDATE CASCADE;



-- ---------------------------------------------------------------------------- hand-written
-- Constraints Prisma cannot express. They are part of the schema contract: keep them when
-- generating later migrations.

ALTER TABLE "source_sync_states"
  ADD CONSTRAINT "source_sync_states_source_known"
    CHECK ("source" IN ('nvd', 'mitre-cve', 'cisa-kev', 'first-epss', 'github-advisory')),
  ADD CONSTRAINT "source_sync_states_failures_non_negative" CHECK ("consecutive_failures" >= 0);
ALTER TABLE "sync_runs"
  ADD CONSTRAINT "sync_runs_source_known"
    CHECK ("source" IN ('nvd', 'mitre-cve', 'cisa-kev', 'first-epss', 'github-advisory')),
  ADD CONSTRAINT "sync_runs_attempt_positive" CHECK ("attempt" >= 1),
  ADD CONSTRAINT "sync_runs_finished_after_start"
    CHECK ("finished_at" IS NULL OR "finished_at" >= "started_at");
ALTER TABLE "source_records"
  ADD CONSTRAINT "source_records_source_known"
    CHECK ("source" IN ('nvd', 'mitre-cve', 'cisa-kev', 'first-epss', 'github-advisory')),
  ADD CONSTRAINT "source_records_cve_id_format"
    CHECK ("cve_id" IS NULL OR "cve_id" ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
  ADD CONSTRAINT "source_records_content_hash_format" CHECK ("content_hash" ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT "source_records_revision_positive" CHECK ("revision" >= 1);
ALTER TABLE "epss_scores"
  ADD CONSTRAINT "epss_scores_cve_id_format" CHECK ("cve_id" ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
  ADD CONSTRAINT "epss_scores_score_range" CHECK ("score" BETWEEN 0 AND 1),
  ADD CONSTRAINT "epss_scores_percentile_range" CHECK ("percentile" BETWEEN 0 AND 1);

-- At most one running run per source (the lease prevents it; this is the last line of defence).
CREATE UNIQUE INDEX "sync_runs_one_running_per_source" ON "sync_runs"("source")
  WHERE "status" = 'running';
