import { createHash, createHmac, timingSafeEqual } from "node:crypto";

/**
 * Canonical JSON: deterministic key ordering, no whitespace.
 * Two objects with the same fields must produce the same string.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return (
    "{" +
    keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") +
    "}"
  );
}

export function sha256Hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

export function hmacSha256Hex(secret: string, input: string): string {
  return createHmac("sha256", secret).update(input).digest("hex");
}

/**
 * Record payload: what actually gets hashed.
 * Keep this shape stable — changing it invalidates every existing chain.
 */
export interface RecordPayload {
  traderId: string;
  sealIndex: number;         // monotonic per trader, starts at 0
  sourceType: "photo" | "voice" | "text" | "correction";
  sourceRef: string;         // e.g. telegram file_id, storage key
  entryCount: number;
  totalAmountCents: number;
  confirmedAt: string;       // ISO 8601 UTC
  entries: Array<{
    lineIndex: number;
    entryType: "sale" | "expense" | "cash_in" | "cash_out";
    description: string;
    amountCents: number;
    entryDate: string;       // ISO 8601 date (YYYY-MM-DD)
    confidence: number;      // 0..1
    wasCorrected: boolean;
  }>;
}

export interface SealedRecord {
  payload: RecordPayload;
  prevHash: string | null;   // null only for sealIndex 0
  recordHash: string;        // sha256(canonicalize(payload) + prevHash)
  hmacSignature: string;     // hmacSha256(secret, recordHash)
}

export function computeRecordHash(
  payload: RecordPayload,
  prevHash: string | null,
): string {
  const canonical = canonicalize(payload);
  const combined = prevHash ? `${prevHash}:${canonical}` : `genesis:${canonical}`;
  return sha256Hex(combined);
}

export function sealRecord(
  payload: RecordPayload,
  prevHash: string | null,
  secret: string,
): SealedRecord {
  const recordHash = computeRecordHash(payload, prevHash);
  const hmacSignature = hmacSha256Hex(secret, recordHash);
  return { payload, prevHash, recordHash, hmacSignature };
}

export type VerifyResult =
  | { ok: true }
  | { ok: false; reason: string; atIndex?: number };

/**
 * Verify an entire chain for one trader.
 * - Hash continuity: each record's prevHash must equal the previous recordHash
 * - Payload integrity: recomputed hash must match stored recordHash
 * - Signature validity: HMAC must match with our secret
 */
export function verifyChain(
  records: SealedRecord[],
  secret: string,
): VerifyResult {
  if (records.length === 0) return { ok: true };

  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    const expectedPrev = i === 0 ? null : records[i - 1].recordHash;

    if (r.prevHash !== expectedPrev) {
      return {
        ok: false,
        reason: `chain break: record ${i} prevHash does not match previous recordHash`,
        atIndex: i,
      };
    }

    const recomputed = computeRecordHash(r.payload, r.prevHash);
    if (recomputed !== r.recordHash) {
      return {
        ok: false,
        reason: `payload altered: record ${i} hash mismatch`,
        atIndex: i,
      };
    }

    const expectedSig = hmacSha256Hex(secret, r.recordHash);
    if (!safeEqualHex(expectedSig, r.hmacSignature)) {
      return {
        ok: false,
        reason: `signature invalid: record ${i} HMAC mismatch`,
        atIndex: i,
      };
    }
  }

  return { ok: true };
}

function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
