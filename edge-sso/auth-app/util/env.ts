import { getSecret } from "fastedge::secret";
import { getEnv } from "fastedge::env";

/** Read a required FastEdge secret, throwing a clear error when it is unset/empty. */
export function requireSecret(key: string): string {
  const value = getSecret(key);
  if (!value) throw new Error(`Missing required secret: ${key}`);
  return value;
}

/** Read a required FastEdge env var, throwing a clear error when it is unset/empty. */
export function requireEnv(key: string): string {
  const value = getEnv(key);
  if (!value) throw new Error(`Missing required env var: ${key}`);
  return value;
}
