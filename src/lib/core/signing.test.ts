import { describe, it, expect } from "vitest";
import {
  canonicalize,
  computeRecordHash,
  sealRecord,
  verifyChain,
  type RecordPayload,
  type SealedRecord,
} from "./signing";

const SECRET = "test-secret-do-not-use-in-prod";

function makePayload(overrides: Partial<RecordPayload> = {}): RecordPayload {
  return {
    traderId: "trader-nomsa",
    sealIndex: 0,
    sourceType: "photo",
    sourceRef: "telegram:file_id_abc",
    entryCount: 2,
    totalAmountCents: 12600,
    confirmedAt: "2026-10-06T18:00:00.000Z",
    entries: [
      {
        lineIndex: 0,
        entryType: "sale",
        description: "Bread x10",
        amountCents: 10000,
        entryDate: "2026-10-06",
        confidence: 0.95,
        wasCorrected: false,
      },
      {
        lineIndex: 1,
        entryType: "sale",
        description: "Airtime",
        amountCents: 2600,
        entryDate: "2026-10-06",
        confidence: 0.9,
        wasCorrected: true,
      },
    ],
    ...overrides,
  };
}

describe("canonicalize", () => {
  it("produces identical output for objects with different key order", () => {
    const a = { b: 2, a: 1 };
    const b = { a: 1, b: 2 };
    expect(canonicalize(a)).toBe(canonicalize(b));
  });

  it("handles nested objects and arrays deterministically", () => {
    const a = { list: [{ y: 2, x: 1 }], top: { z: 3, a: 4 } };
    const b = { top: { a: 4, z: 3 }, list: [{ x: 1, y: 2 }] };
    expect(canonicalize(a)).toBe(canonicalize(b));
  });
});

describe("signing + verification", () => {
  it("seals and verifies a single record", () => {
    const sealed = sealRecord(makePayload(), null, SECRET);
    expect(verifyChain([sealed], SECRET)).toEqual({ ok: true });
  });

  it("seals and verifies a chain of 3 records", () => {
    const r0 = sealRecord(makePayload({ sealIndex: 0 }), null, SECRET);
    const r1 = sealRecord(makePayload({ sealIndex: 1 }), r0.recordHash, SECRET);
    const r2 = sealRecord(makePayload({ sealIndex: 2 }), r1.recordHash, SECRET);
    expect(verifyChain([r0, r1, r2], SECRET)).toEqual({ ok: true });
  });

  it("detects a tampered payload", () => {
    const r0 = sealRecord(makePayload({ sealIndex: 0 }), null, SECRET);
    const r1 = sealRecord(makePayload({ sealIndex: 1 }), r0.recordHash, SECRET);

    const tampered: SealedRecord = {
      ...r1,
      payload: { ...r1.payload, totalAmountCents: 999999 },
    };

    const result = verifyChain([r0, tampered], SECRET);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.atIndex).toBe(1);
      expect(result.reason).toContain("payload altered");
    }
  });

  it("detects a broken chain link", () => {
    const r0 = sealRecord(makePayload({ sealIndex: 0 }), null, SECRET);
    const r1 = sealRecord(makePayload({ sealIndex: 1 }), r0.recordHash, SECRET);
    const r2 = sealRecord(makePayload({ sealIndex: 2 }), r1.recordHash, SECRET);

    const result = verifyChain([r0, r2], SECRET);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.atIndex).toBe(1);
      expect(result.reason).toContain("chain break");
    }
  });

  it("detects a forged HMAC signature", () => {
    const r0 = sealRecord(makePayload(), null, SECRET);
    const forged: SealedRecord = {
      ...r0,
      hmacSignature: "0".repeat(64),
    };
    const result = verifyChain([forged], SECRET);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("signature invalid");
    }
  });

  it("rejects verification with the wrong secret", () => {
    const r0 = sealRecord(makePayload(), null, SECRET);
    const result = verifyChain([r0], "wrong-secret");
    expect(result.ok).toBe(false);
  });

  it("detects tampering even in the middle of a long chain", () => {
    const records: SealedRecord[] = [];
    let prev: string | null = null;
    for (let i = 0; i < 10; i++) {
      const r = sealRecord(makePayload({ sealIndex: i }), prev, SECRET);
      records.push(r);
      prev = r.recordHash;
    }

    records[4] = {
      ...records[4],
      payload: { ...records[4].payload, totalAmountCents: 1 },
    };

    const result = verifyChain(records, SECRET);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.atIndex).toBe(4);
    }
  });
});

describe("computeRecordHash", () => {
  it("is deterministic for the same payload + prevHash", () => {
    const p = makePayload();
    expect(computeRecordHash(p, null)).toBe(computeRecordHash(p, null));
    expect(computeRecordHash(p, "abc")).toBe(computeRecordHash(p, "abc"));
  });

  it("differs when prevHash differs", () => {
    const p = makePayload();
    expect(computeRecordHash(p, "a")).not.toBe(computeRecordHash(p, "b"));
  });

  it("differs when payload differs", () => {
    const p1 = makePayload();
    const p2 = makePayload({ totalAmountCents: 1 });
    expect(computeRecordHash(p1, null)).not.toBe(computeRecordHash(p2, null));
  });
});
