import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { randomUUID } from "node:crypto";
import { eq, inArray } from "drizzle-orm";
import { db, schema } from "@/lib/db/client";
import {
  sealNewRecord,
  loadTraderChain,
  verifyTraderChain,
  getChainHead,
  type SealInput,
} from "./record-store";

const TEST_TRADER_ID = `test-trader-${randomUUID()}`;

function makeEntries(n = 2): SealInput["entries"] {
  return Array.from({ length: n }, (_, i) => ({
    lineIndex: i,
    entryType: "sale" as const,
    description: `Test sale ${i}`,
    amountCents: 1000 + i * 100,
    entryDate: "2026-10-06",
    confidence: 0.95,
    wasCorrected: false,
  }));
}

beforeAll(async () => {
  const now = new Date();
  await db.insert(schema.traders).values({
    id: TEST_TRADER_ID,
    channel: "telegram",
    channelUserId: `chat-${TEST_TRADER_ID}`,
    displayName: "Integration Test Trader",
    language: "en",
    createdAt: now,
    updatedAt: now,
  });
});

afterAll(async () => {
  const recordIds = await db
    .select({ id: schema.records.id })
    .from(schema.records)
    .where(eq(schema.records.traderId, TEST_TRADER_ID));

  if (recordIds.length > 0) {
    await db.delete(schema.entries).where(
      inArray(
        schema.entries.recordId,
        recordIds.map((r) => r.id),
      ),
    );
  }

  await db
    .delete(schema.records)
    .where(eq(schema.records.traderId, TEST_TRADER_ID));

  await db
    .delete(schema.auditLog)
    .where(eq(schema.auditLog.actor, TEST_TRADER_ID));

  await db.delete(schema.traders).where(eq(schema.traders.id, TEST_TRADER_ID));
});

describe("record-store integration", () => {
  it("seals a first record with prevHash = null and sealIndex = 0", async () => {
    const out = await sealNewRecord({
      traderId: TEST_TRADER_ID,
      sourceType: "photo",
      sourceRef: "test:first",
      entries: makeEntries(2),
    });

    expect(out.sealIndex).toBe(0);
    expect(out.prevHash).toBeNull();
    expect(out.recordHash).toMatch(/^[0-9a-f]{64}$/);
    expect(out.hmacSignature).toMatch(/^[0-9a-f]{64}$/);
    expect(out.entryCount).toBe(2);
    expect(out.totalAmountCents).toBe(1000 + 1100);
  });

  it("seals a chain of 3 records with linked prevHash values", async () => {
    const r1 = await sealNewRecord({
      traderId: TEST_TRADER_ID,
      sourceType: "photo",
      sourceRef: "test:second",
      entries: makeEntries(1),
    });
    expect(r1.sealIndex).toBe(1);
    expect(r1.prevHash).not.toBeNull();

    const r2 = await sealNewRecord({
      traderId: TEST_TRADER_ID,
      sourceType: "voice",
      sourceRef: "test:third",
      entries: makeEntries(3),
    });
    expect(r2.sealIndex).toBe(2);
    expect(r2.prevHash).toBe(r1.recordHash);
  });

  it("loads the chain in order and verifies it", async () => {
    const chain = await loadTraderChain(TEST_TRADER_ID);
    expect(chain.length).toBe(3);
    expect(chain[0].prevHash).toBeNull();
    expect(chain[1].prevHash).toBe(chain[0].recordHash);
    expect(chain[2].prevHash).toBe(chain[1].recordHash);

    const result = await verifyTraderChain(TEST_TRADER_ID);
    expect(result).toEqual({ ok: true });
  });

  it("returns the correct chain head", async () => {
    const head = await getChainHead(TEST_TRADER_ID);
    expect(head).not.toBeNull();
    expect(head!.sealIndex).toBe(2);

    const chain = await loadTraderChain(TEST_TRADER_ID);
    expect(head!.recordHash).toBe(chain[2].recordHash);
  });

  it("detects a tampered payload_json", async () => {
    const chain = await loadTraderChain(TEST_TRADER_ID);
    const targetRecord = chain[1];

    const tampered = {
      ...targetRecord.payload,
      totalAmountCents: 99999999,
    };

    await db
      .update(schema.records)
      .set({ payloadJson: JSON.stringify(tampered) })
      .where(eq(schema.records.recordHash, targetRecord.recordHash));

    const result = await verifyTraderChain(TEST_TRADER_ID);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.atIndex).toBe(1);
      expect(result.reason).toMatch(/payload altered/);
    }

    await db
      .update(schema.records)
      .set({ payloadJson: JSON.stringify(targetRecord.payload) })
      .where(eq(schema.records.recordHash, targetRecord.recordHash));

    const restored = await verifyTraderChain(TEST_TRADER_ID);
    expect(restored).toEqual({ ok: true });
  });
});