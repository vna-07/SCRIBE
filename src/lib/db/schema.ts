import {
  sqliteTable,
  text,
  integer,
  real,
  index,
  uniqueIndex,
} from "drizzle-orm/sqlite-core";

// ---------------------------------------------------------------------------
// traders
// ---------------------------------------------------------------------------
// One row per human. A trader arrives via a channel (Telegram today, WhatsApp
// later) and is identified by (channel, channelUserId). Nothing else is
// required to start; language defaults to isiXhosa.
// ---------------------------------------------------------------------------

export const traders = sqliteTable(
  "traders",
  {
    id: text("id").primaryKey(),
    channel: text("channel", {
      enum: ["telegram", "whatsapp", "ussd"],
    }).notNull(),
    channelUserId: text("channel_user_id").notNull(),
    displayName: text("display_name"),
    language: text("language").notNull().default("xh"),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
    updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
  },
  (t) => ({
    channelUserUnique: uniqueIndex("traders_channel_user_unique").on(
      t.channel,
      t.channelUserId,
    ),
  }),
);

// ---------------------------------------------------------------------------
// records
// ---------------------------------------------------------------------------
// One row per sealed Trading Record. Fields mirror the SealedRecord shape from
// src/lib/core/signing.ts so the row can be reconstructed and re-verified.
//
//   payloadJson  — full canonical payload (the thing that was hashed)
//   recordHash   — sha256(prevHash : canonicalize(payload))
//   prevHash     — previous record's recordHash, null for the first record
//   hmacSignature— hmacSha256(HMAC_SECRET, recordHash)
//
// The (trader_id, seal_index) pair is unique, so a trader can never have two
// records claiming the same position in their chain.
// ---------------------------------------------------------------------------

export const records = sqliteTable(
  "records",
  {
    id: text("id").primaryKey(),
    traderId: text("trader_id")
      .notNull()
      .references(() => traders.id),
    sealIndex: integer("seal_index").notNull(),
    sourceType: text("source_type", {
      enum: ["photo", "voice", "text", "correction"],
    }).notNull(),
    sourceRef: text("source_ref").notNull(),
    entryCount: integer("entry_count").notNull(),
    totalAmountCents: integer("total_amount_cents").notNull(),
    confirmedAt: integer("confirmed_at", { mode: "timestamp_ms" }).notNull(),
    prevHash: text("prev_hash"),
    recordHash: text("record_hash").notNull(),
    hmacSignature: text("hmac_signature").notNull(),
    payloadJson: text("payload_json").notNull(),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  },
  (t) => ({
    traderSealUnique: uniqueIndex("records_trader_seal_unique").on(
      t.traderId,
      t.sealIndex,
    ),
    traderIdx: index("records_trader_idx").on(t.traderId),
  }),
);

// ---------------------------------------------------------------------------
// entries
// ---------------------------------------------------------------------------
// The lines inside a record. Kept as separate rows so we can query across
// records later (top items, day-of-week patterns, cash-flow totals) without
// parsing payloadJson every time.
// ---------------------------------------------------------------------------

export const entries = sqliteTable(
  "entries",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    recordId: text("record_id")
      .notNull()
      .references(() => records.id),
    lineIndex: integer("line_index").notNull(),
    entryType: text("entry_type", {
      enum: ["sale", "expense", "cash_in", "cash_out"],
    }).notNull(),
    description: text("description").notNull(),
    amountCents: integer("amount_cents").notNull(),
    entryDate: text("entry_date").notNull(), // YYYY-MM-DD
    confidence: real("confidence").notNull(), // 0..1
    wasCorrected: integer("was_corrected", { mode: "boolean" }).notNull(),
  },
  (t) => ({
    recordIdx: index("entries_record_idx").on(t.recordId),
  }),
);

// ---------------------------------------------------------------------------
// audit_log
// ---------------------------------------------------------------------------
// Every privileged action (sealing, sharing, score recompute, verifier
// access) writes one row. This is the paper trail the pitch promises.
// ---------------------------------------------------------------------------

export const auditLog = sqliteTable(
  "audit_log",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    actor: text("actor").notNull(),
    action: text("action").notNull(),
    targetType: text("target_type"),
    targetId: text("target_id"),
    detailsJson: text("details_json"),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
  },
  (t) => ({
    createdIdx: index("audit_log_created_idx").on(t.createdAt),
  }),
);

// ---------------------------------------------------------------------------
// inferred types
// ---------------------------------------------------------------------------

export type Trader = typeof traders.$inferSelect;
export type NewTrader = typeof traders.$inferInsert;
export type RecordRow = typeof records.$inferSelect;
export type NewRecord = typeof records.$inferInsert;
export type EntryRow = typeof entries.$inferSelect;
export type NewEntry = typeof entries.$inferInsert;
export type AuditLogRow = typeof auditLog.$inferSelect;
export type NewAuditLog = typeof auditLog.$inferInsert;