import { randomUUID } from "node:crypto";
import { desc, eq, asc } from "drizzle-orm";
import { db, schema } from "@/lib/db/client";
import {
  canonicalize,
  sealRecord,
  verifyChain,
  type RecordPayload,
  type SealedRecord,
  type VerifyResult,
} from "./signing";

// ---------------------------------------------------------------------------
// Input / output shapes
// ---------------------------------------------------------------------------

export interface SealInput {
  traderId: string;
  sourceType: "photo" | "voice" | "text" | "correction";
  sourceRef: string;
  entries: Array<{
    lineIndex: number;
    entryType: "sale" | "expense" | "cash_in" | "cash_out";
    description: string;
    amountCents: number;
    entryDate: string;
    confidence: number;
    wasCorrected: boolean;
  }>;
}

export interface SealOutput {
  recordId: string;
  sealIndex: number;
  prevHash: string | null;
  recordHash: string;
  hmacSignature: string;
  totalAmountCents: number;
  entryCount: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getSecret(): string {
  const s = process.env.HMAC_SECRET;
  if (!s) {
    throw new Error("HMAC_SECRET is not set");
  }
  return s;
}

// ---------------------------------------------------------------------------
// sealNewRecord
// ---------------------------------------------------------------------------

export async function sealNewRecord(input: SealInput): Promise<SealOutput> {
  const secret = getSecret();

  const headRows = await db
    .select({
      recordHash: schema.records.recordHash,
      sealIndex: schema.records.sealIndex,
    })
    .from(schema.records)
    .where(eq(schema.records.traderId, input.traderId))
    .orderBy(desc(schema.records.sealIndex))
    .limit(1);

  const prevHash = headRows[0]?.recordHash ?? null;
  const sealIndex = headRows[0] ? headRows[0].sealIndex + 1 : 0;

  const confirmedAt = new Date().toISOString();
  const totalAmountCents = input.entries.reduce(
    (sum, e) => sum + e.amountCents,
    0,
  );

  const payload: RecordPayload = {
    traderId: input.traderId,
    sealIndex,
    sourceType: input.sourceType,
    sourceRef: input.sourceRef,
    entryCount: input.entries.length,
    totalAmountCents,
    confirmedAt,
    entries: input.entries,
  };

  const sealed = sealRecord(payload, prevHash, secret);

  const recordId = randomUUID();
  const now = new Date();
  const canonicalPayload = canonicalize(payload);

  await db.transaction(async (tx) => {
    await tx.insert(schema.records).values({
      id: recordId,
      traderId: input.traderId,
      sealIndex,
      sourceType: input.sourceType,
      sourceRef: input.sourceRef,
      entryCount: payload.entryCount,
      totalAmountCents: payload.totalAmountCents,
      confirmedAt: new Date(payload.confirmedAt),
      prevHash: sealed.prevHash,
      recordHash: sealed.recordHash,
      hmacSignature: sealed.hmacSignature,
      payloadJson: canonicalPayload,
      createdAt: now,
    });

    if (input.entries.length > 0) {
      await tx.insert(schema.entries).values(
        input.entries.map((e) => ({
          recordId,
          lineIndex: e.lineIndex,
          entryType: e.entryType,
          description: e.description,
          amountCents: e.amountCents,
          entryDate: e.entryDate,
          confidence: e.confidence,
          wasCorrected: e.wasCorrected,
        })),
      );
    }

    await tx.insert(schema.auditLog).values({
      actor: input.traderId,
      action: "record.sealed",
      targetType: "record",
      targetId: recordId,
      detailsJson: JSON.stringify({
        sealIndex,
        recordHash: sealed.recordHash,
        entryCount: payload.entryCount,
        totalAmountCents: payload.totalAmountCents,
      }),
      createdAt: now,
    });
  });

  return {
    recordId,
    sealIndex,
    prevHash: sealed.prevHash,
    recordHash: sealed.recordHash,
    hmacSignature: sealed.hmacSignature,
    totalAmountCents,
    entryCount: payload.entryCount,
  };
}

// ---------------------------------------------------------------------------
// loadTraderChain
// ---------------------------------------------------------------------------

export async function loadTraderChain(
  traderId: string,
): Promise<SealedRecord[]> {
  const rows = await db
    .select()
    .from(schema.records)
    .where(eq(schema.records.traderId, traderId))
    .orderBy(asc(schema.records.sealIndex));

  return rows.map((r) => ({
    payload: JSON.parse(r.payloadJson) as RecordPayload,
    prevHash: r.prevHash,
    recordHash: r.recordHash,
    hmacSignature: r.hmacSignature,
  }));
}

// ---------------------------------------------------------------------------
// verifyTraderChain
// ---------------------------------------------------------------------------

export async function verifyTraderChain(
  traderId: string,
): Promise<VerifyResult> {
  const chain = await loadTraderChain(traderId);
  return verifyChain(chain, getSecret());
}

// ---------------------------------------------------------------------------
// getChainHead
// ---------------------------------------------------------------------------

export async function getChainHead(traderId: string): Promise<{
  sealIndex: number;
  recordHash: string;
  recordId: string;
  confirmedAt: Date;
} | null> {
  const rows = await db
    .select({
      sealIndex: schema.records.sealIndex,
      recordHash: schema.records.recordHash,
      recordId: schema.records.id,
      confirmedAt: schema.records.confirmedAt,
    })
    .from(schema.records)
    .where(eq(schema.records.traderId, traderId))
    .orderBy(desc(schema.records.sealIndex))
    .limit(1);

  return rows[0] ?? null;
}