-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "catalog_origin" AS ENUM ('curated', 'discovered');

-- CreateEnum
CREATE TYPE "product_type" AS ENUM ('application', 'operating-system', 'hardware', 'unknown');

-- CreateEnum
CREATE TYPE "product_identifier_type" AS ENUM ('purl', 'swid', 'vendor-sku', 'other');

-- CreateEnum
CREATE TYPE "affected_status" AS ENUM ('affected', 'unaffected', 'unknown');

-- CreateEnum
CREATE TYPE "association_origin" AS ENUM ('observation', 'manual');

-- CreateEnum
CREATE TYPE "history_change" AS ENUM ('added', 'ranges-changed', 'withdrawn', 'restored');

-- CreateEnum
CREATE TYPE "cve_state" AS ENUM ('published', 'rejected');

-- CreateEnum
CREATE TYPE "severity" AS ENUM ('none', 'low', 'medium', 'high', 'critical', 'unknown');

-- CreateTable
CREATE TABLE "vendors" (
    "id" UUID NOT NULL,
    "slug" VARCHAR(128) NOT NULL,
    "name" VARCHAR(128) NOT NULL,
    "description" VARCHAR(4000),
    "website" VARCHAR(2048),
    "origin" "catalog_origin" NOT NULL DEFAULT 'curated',
    "source" VARCHAR(128) NOT NULL,
    "product_count" INTEGER NOT NULL DEFAULT 0,
    "cve_count" INTEGER NOT NULL DEFAULT 0,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "vendors_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "products" (
    "id" UUID NOT NULL,
    "vendor_id" UUID NOT NULL,
    "slug" VARCHAR(128) NOT NULL,
    "name" VARCHAR(128) NOT NULL,
    "type" "product_type" NOT NULL DEFAULT 'unknown',
    "description" VARCHAR(4000),
    "website" VARCHAR(2048),
    "origin" "catalog_origin" NOT NULL DEFAULT 'curated',
    "source" VARCHAR(128) NOT NULL,
    "cve_count" INTEGER NOT NULL DEFAULT 0,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "products_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "product_cpes" (
    "id" UUID NOT NULL,
    "product_id" UUID NOT NULL,
    "cpe" VARCHAR(512) NOT NULL,
    "part" VARCHAR(1) NOT NULL,
    "cpe_vendor" VARCHAR(256) NOT NULL,
    "cpe_product" VARCHAR(256) NOT NULL,
    "cpe_version" VARCHAR(256) NOT NULL,
    "source" VARCHAR(128) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "product_cpes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "product_identifiers" (
    "id" UUID NOT NULL,
    "product_id" UUID NOT NULL,
    "type" "product_identifier_type" NOT NULL,
    "value" VARCHAR(512) NOT NULL,
    "source" VARCHAR(128) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "product_identifiers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cve_product_associations" (
    "id" UUID NOT NULL,
    "cve_id" VARCHAR(32) NOT NULL,
    "product_id" UUID NOT NULL,
    "vendor_id" UUID NOT NULL,
    "source" VARCHAR(128) NOT NULL,
    "source_record_id" VARCHAR(128) NOT NULL,
    "source_url" VARCHAR(2048),
    "attribution" VARCHAR(512),
    "origin" "association_origin" NOT NULL,
    "status" "affected_status" NOT NULL,
    "note" VARCHAR(2000),
    "first_seen_at" TIMESTAMPTZ(3) NOT NULL,
    "last_seen_at" TIMESTAMPTZ(3) NOT NULL,
    "withdrawn_at" TIMESTAMPTZ(3),

    CONSTRAINT "cve_product_associations_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "affected_version_ranges" (
    "id" UUID NOT NULL,
    "association_id" UUID NOT NULL,
    "range_key" VARCHAR(1400) NOT NULL,
    "status" "affected_status" NOT NULL,
    "cpe" VARCHAR(512),
    "version" VARCHAR(128),
    "version_start_including" VARCHAR(128),
    "version_start_excluding" VARCHAR(128),
    "version_end_including" VARCHAR(128),
    "version_end_excluding" VARCHAR(128),

    CONSTRAINT "affected_version_ranges_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "product_vulnerability_history" (
    "id" UUID NOT NULL,
    "product_id" UUID NOT NULL,
    "association_id" UUID NOT NULL,
    "cve_id" VARCHAR(32) NOT NULL,
    "change" "history_change" NOT NULL,
    "source" VARCHAR(128) NOT NULL,
    "source_record_id" VARCHAR(128) NOT NULL,
    "ranges" JSONB NOT NULL,
    "occurred_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "product_vulnerability_history_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "observation_cursors" (
    "id" UUID NOT NULL,
    "source" VARCHAR(128) NOT NULL,
    "source_record_id" VARCHAR(128) NOT NULL,
    "cve_id" VARCHAR(32) NOT NULL,
    "revision" INTEGER NOT NULL,
    "content_hash" CHAR(64) NOT NULL,
    "observed_at" TIMESTAMPTZ(3) NOT NULL,
    "applied_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "observation_cursors_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cve_facts" (
    "id" UUID NOT NULL,
    "cve_id" VARCHAR(32) NOT NULL,
    "record_id" UUID NOT NULL,
    "record_version" INTEGER NOT NULL,
    "state" "cve_state" NOT NULL,
    "severity" "severity" NOT NULL,
    "cvss_score" DECIMAL(3,1),
    "in_kev" BOOLEAN NOT NULL,
    "epss_score" DECIMAL(10,9),
    "epss_percentile" DECIMAL(10,9),
    "published_at" TIMESTAMPTZ(3),
    "deleted_at" TIMESTAMPTZ(3),
    "event_occurred_at" TIMESTAMPTZ(3) NOT NULL,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "cve_facts_pkey" PRIMARY KEY ("id")
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
CREATE UNIQUE INDEX "vendors_slug_key" ON "vendors"("slug");

-- CreateIndex
CREATE INDEX "vendors_name_idx" ON "vendors"("name");

-- CreateIndex
CREATE INDEX "vendors_origin_idx" ON "vendors"("origin");

-- CreateIndex
CREATE INDEX "vendors_cve_count_id_idx" ON "vendors"("cve_count" DESC, "id");

-- CreateIndex
CREATE INDEX "vendors_product_count_id_idx" ON "vendors"("product_count" DESC, "id");

-- CreateIndex
CREATE INDEX "products_name_idx" ON "products"("name");

-- CreateIndex
CREATE INDEX "products_type_idx" ON "products"("type");

-- CreateIndex
CREATE INDEX "products_origin_idx" ON "products"("origin");

-- CreateIndex
CREATE INDEX "products_cve_count_id_idx" ON "products"("cve_count" DESC, "id");

-- CreateIndex
CREATE UNIQUE INDEX "products_vendor_id_slug_key" ON "products"("vendor_id", "slug");

-- CreateIndex
CREATE UNIQUE INDEX "product_cpes_cpe_key" ON "product_cpes"("cpe");

-- CreateIndex
CREATE INDEX "product_cpes_cpe_vendor_cpe_product_idx" ON "product_cpes"("cpe_vendor", "cpe_product");

-- CreateIndex
CREATE INDEX "product_cpes_product_id_idx" ON "product_cpes"("product_id");

-- CreateIndex
CREATE INDEX "product_identifiers_value_idx" ON "product_identifiers"("value");

-- CreateIndex
CREATE INDEX "product_identifiers_product_id_idx" ON "product_identifiers"("product_id");

-- CreateIndex
CREATE UNIQUE INDEX "product_identifiers_type_value_key" ON "product_identifiers"("type", "value");

-- CreateIndex
CREATE INDEX "cve_product_associations_product_id_withdrawn_at_idx" ON "cve_product_associations"("product_id", "withdrawn_at");

-- CreateIndex
CREATE INDEX "cve_product_associations_vendor_id_withdrawn_at_idx" ON "cve_product_associations"("vendor_id", "withdrawn_at");

-- CreateIndex
CREATE INDEX "cve_product_associations_cve_id_idx" ON "cve_product_associations"("cve_id");

-- CreateIndex
CREATE INDEX "cve_product_associations_source_source_record_id_idx" ON "cve_product_associations"("source", "source_record_id");

-- CreateIndex
CREATE UNIQUE INDEX "cve_product_associations_cve_id_product_id_source_source_re_key" ON "cve_product_associations"("cve_id", "product_id", "source", "source_record_id");

-- CreateIndex
CREATE UNIQUE INDEX "affected_version_ranges_association_id_range_key_key" ON "affected_version_ranges"("association_id", "range_key");

-- CreateIndex
CREATE INDEX "product_vulnerability_history_product_id_occurred_at_id_idx" ON "product_vulnerability_history"("product_id", "occurred_at" DESC, "id");

-- CreateIndex
CREATE INDEX "product_vulnerability_history_cve_id_idx" ON "product_vulnerability_history"("cve_id");

-- CreateIndex
CREATE INDEX "observation_cursors_cve_id_idx" ON "observation_cursors"("cve_id");

-- CreateIndex
CREATE UNIQUE INDEX "observation_cursors_source_source_record_id_key" ON "observation_cursors"("source", "source_record_id");

-- CreateIndex
CREATE UNIQUE INDEX "cve_facts_cve_id_key" ON "cve_facts"("cve_id");

-- CreateIndex
CREATE INDEX "cve_facts_severity_idx" ON "cve_facts"("severity");

-- CreateIndex
CREATE INDEX "processed_events_processed_at_idx" ON "processed_events"("processed_at");

-- CreateIndex
CREATE UNIQUE INDEX "processed_events_consumer_event_id_key" ON "processed_events"("consumer", "event_id");

-- CreateIndex
CREATE UNIQUE INDEX "outbox_events_event_id_key" ON "outbox_events"("event_id");

-- CreateIndex
CREATE INDEX "outbox_events_published_at_next_attempt_at_idx" ON "outbox_events"("published_at", "next_attempt_at");

-- AddForeignKey
ALTER TABLE "products" ADD CONSTRAINT "products_vendor_id_fkey" FOREIGN KEY ("vendor_id") REFERENCES "vendors"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "product_cpes" ADD CONSTRAINT "product_cpes_product_id_fkey" FOREIGN KEY ("product_id") REFERENCES "products"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "product_identifiers" ADD CONSTRAINT "product_identifiers_product_id_fkey" FOREIGN KEY ("product_id") REFERENCES "products"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cve_product_associations" ADD CONSTRAINT "cve_product_associations_product_id_fkey" FOREIGN KEY ("product_id") REFERENCES "products"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "affected_version_ranges" ADD CONSTRAINT "affected_version_ranges_association_id_fkey" FOREIGN KEY ("association_id") REFERENCES "cve_product_associations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "product_vulnerability_history" ADD CONSTRAINT "product_vulnerability_history_product_id_fkey" FOREIGN KEY ("product_id") REFERENCES "products"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "product_vulnerability_history" ADD CONSTRAINT "product_vulnerability_history_association_id_fkey" FOREIGN KEY ("association_id") REFERENCES "cve_product_associations"("id") ON DELETE CASCADE ON UPDATE CASCADE;



-- ---------------------------------------------------------------------------- hand-written
-- Constraints Prisma cannot express. They are part of the schema contract: keep them when
-- generating later migrations.

-- Defence in depth for values the API already validates.
ALTER TABLE "vendors"
  ADD CONSTRAINT "vendors_slug_format" CHECK ("slug" ~ '^[a-z0-9][a-z0-9._+-]{0,127}$'),
  ADD CONSTRAINT "vendors_counts_positive" CHECK ("product_count" >= 0 AND "cve_count" >= 0),
  ADD CONSTRAINT "vendors_version_positive" CHECK ("version" >= 1);
ALTER TABLE "products"
  ADD CONSTRAINT "products_slug_format" CHECK ("slug" ~ '^[a-z0-9][a-z0-9._+-]{0,127}$'),
  ADD CONSTRAINT "products_cve_count_positive" CHECK ("cve_count" >= 0),
  ADD CONSTRAINT "products_version_positive" CHECK ("version" >= 1);
ALTER TABLE "product_cpes"
  ADD CONSTRAINT "product_cpes_format" CHECK ("cpe" LIKE 'cpe:2.3:%'),
  ADD CONSTRAINT "product_cpes_part" CHECK ("part" IN ('a', 'o', 'h', '*', '-'));
ALTER TABLE "cve_product_associations"
  ADD CONSTRAINT "cve_product_associations_cve_id_format" CHECK ("cve_id" ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
  ADD CONSTRAINT "cve_product_associations_seen_order" CHECK ("last_seen_at" >= "first_seen_at");
ALTER TABLE "cve_facts"
  ADD CONSTRAINT "cve_facts_cve_id_format" CHECK ("cve_id" ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
  ADD CONSTRAINT "cve_facts_cvss_score_range" CHECK ("cvss_score" BETWEEN 0 AND 10),
  ADD CONSTRAINT "cve_facts_epss_score_range" CHECK ("epss_score" BETWEEN 0 AND 1),
  ADD CONSTRAINT "cve_facts_epss_percentile_range" CHECK ("epss_percentile" BETWEEN 0 AND 1);
ALTER TABLE "observation_cursors"
  ADD CONSTRAINT "observation_cursors_revision_positive" CHECK ("revision" >= 1);

-- Case-insensitive substring search (`q`) over vendor and product names and slugs. pg_trgm is a
-- trusted extension, so the database owner (the service role) may create it.
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE INDEX "vendors_name_trgm_idx" ON "vendors" USING GIN ("name" gin_trgm_ops);
CREATE INDEX "vendors_slug_trgm_idx" ON "vendors" USING GIN ("slug" gin_trgm_ops);
CREATE INDEX "products_name_trgm_idx" ON "products" USING GIN ("name" gin_trgm_ops);
CREATE INDEX "products_slug_trgm_idx" ON "products" USING GIN ("slug" gin_trgm_ops);
