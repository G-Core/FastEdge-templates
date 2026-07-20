import { KvStore } from "fastedge::kv";

export const DEFAULT_KEY_PREFIX = "totp:";

/**
 * Read a TOTP seed for a given userId from KV.
 * Returns the base32-encoded seed string, or null if not enrolled.
 */
export function readSeed(storeName: string, userId: string, keyPrefix = DEFAULT_KEY_PREFIX): string | null {
  const store = KvStore.open(storeName);
  const buf = store.get(keyPrefix + userId);
  if (!buf) return null;
  return new TextDecoder().decode(buf);
}

/**
 * Write a TOTP seed for a given userId via the Gcore KV REST API.
 * The fastedge::kv SDK is read-only — writes go through the management API.
 *
 * API: PUT /fastedge/v1/kv/{storeId}/data
 * Body: array of { key, datatype, op, payload: { value, encoding } } entries.
 * The seed is stored with encoding "plain" — see context/security/threat-model.md
 * (R4) for the at-rest implications.
 */
export async function writeSeed(
  apiUrl: string,
  apiToken: string,
  storeId: string,
  userId: string,
  seed: string,
  keyPrefix = DEFAULT_KEY_PREFIX,
): Promise<void> {
  const url = `${apiUrl}/fastedge/v1/kv/${storeId}/data`;
  const headers = { "Content-Type": "application/json", Authorization: `APIKey ${apiToken}` };
  const body = JSON.stringify([
    { key: keyPrefix + userId, datatype: "kv", op: "add", payload: { value: seed, encoding: "plain" } },
  ]);
  const res = await fetch(url, { method: "PUT", headers, body });
  if (!res.ok) {
    const errBody = await res.text().catch(() => "");
    throw new Error(`KV write failed: ${res.status} ${errBody}`);
  }
}

/**
 * Check whether a user already has a seed enrolled.
 * Used to guard against silent re-enrollment.
 */
export function isEnrolled(storeName: string, userId: string, keyPrefix = DEFAULT_KEY_PREFIX): boolean {
  return readSeed(storeName, userId, keyPrefix) !== null;
}
