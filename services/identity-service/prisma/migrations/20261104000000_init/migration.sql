-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "audit_outcome" AS ENUM ('success', 'failure', 'denied');

-- CreateEnum
CREATE TYPE "audit_actor_type" AS ENUM ('user', 'service', 'system', 'anonymous');

-- CreateTable
CREATE TABLE "user_profiles" (
    "id" UUID NOT NULL,
    "keycloak_user_id" UUID NOT NULL,
    "username" VARCHAR(255) NOT NULL,
    "email" VARCHAR(320),
    "display_name" VARCHAR(100),
    "job_title" VARCHAR(100),
    "timezone" VARCHAR(64) NOT NULL DEFAULT 'UTC',
    "first_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "user_profiles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_events" (
    "id" UUID NOT NULL,
    "occurred_at" TIMESTAMPTZ(3) NOT NULL,
    "recorded_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "source" VARCHAR(64) NOT NULL,
    "source_event_id" VARCHAR(128),
    "action" VARCHAR(128) NOT NULL,
    "outcome" "audit_outcome" NOT NULL,
    "actor_type" "audit_actor_type" NOT NULL,
    "actor_id" VARCHAR(128),
    "actor_username" VARCHAR(255),
    "resource_type" VARCHAR(64),
    "resource_id" VARCHAR(128),
    "ip_address" VARCHAR(64),
    "user_agent" VARCHAR(512),
    "correlation_id" VARCHAR(128),
    "details" JSONB,

    CONSTRAINT "audit_events_pkey" PRIMARY KEY ("id")
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

-- CreateTable
CREATE TABLE "sync_cursors" (
    "name" VARCHAR(64) NOT NULL,
    "position" BIGINT NOT NULL,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "sync_cursors_pkey" PRIMARY KEY ("name")
);

-- CreateIndex
CREATE UNIQUE INDEX "user_profiles_keycloak_user_id_key" ON "user_profiles"("keycloak_user_id");

-- CreateIndex
CREATE INDEX "user_profiles_username_idx" ON "user_profiles"("username");

-- CreateIndex
CREATE INDEX "audit_events_occurred_at_idx" ON "audit_events"("occurred_at" DESC);

-- CreateIndex
CREATE INDEX "audit_events_actor_id_occurred_at_idx" ON "audit_events"("actor_id", "occurred_at" DESC);

-- CreateIndex
CREATE INDEX "audit_events_action_occurred_at_idx" ON "audit_events"("action", "occurred_at" DESC);

-- CreateIndex
CREATE INDEX "audit_events_resource_type_resource_id_idx" ON "audit_events"("resource_type", "resource_id");

-- CreateIndex
CREATE UNIQUE INDEX "audit_events_source_source_event_id_key" ON "audit_events"("source", "source_event_id");

-- CreateIndex
CREATE UNIQUE INDEX "outbox_events_event_id_key" ON "outbox_events"("event_id");

-- CreateIndex
CREATE INDEX "outbox_events_published_at_next_attempt_at_idx" ON "outbox_events"("published_at", "next_attempt_at");


-- The audit trail is append-only: entries can be inserted but never changed or removed by the
-- application role. Retention, when introduced, runs as a separate, audited maintenance task.
CREATE FUNCTION "audit_events_reject_modification"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only (% rejected)', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER "audit_events_append_only"
  BEFORE UPDATE OR DELETE ON "audit_events"
  FOR EACH ROW EXECUTE FUNCTION "audit_events_reject_modification"();

CREATE TRIGGER "audit_events_no_truncate"
  BEFORE TRUNCATE ON "audit_events"
  FOR EACH STATEMENT EXECUTE FUNCTION "audit_events_reject_modification"();
