import { SamlConfig } from "./config.js";
import { base64Encode, encodeUtf8 } from "../../util/bytes";

/** Generates a SAML AuthnRequest ID (`_` + 32 hex chars). */
export function generateRequestId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return (
    "_" +
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

/**
 * Escape a value for safe interpolation into XML attribute/text content. The
 * config values below are operator-controlled (not attacker input), so this is
 * robustness, not an injection fix: an unescaped `&`, `<`, or `"` in a SAML URL
 * or entity ID would otherwise produce malformed XML and an opaque IdP error.
 */
function escapeXml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function buildAuthnRequestXml(config: SamlConfig, id: string, issueInstant: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="${id}"
  Version="2.0"
  IssueInstant="${issueInstant}"
  Destination="${escapeXml(config.idpSsoUrl)}"
  AssertionConsumerServiceURL="${escapeXml(config.spAcsUrl)}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>${escapeXml(config.spEntityId)}</saml:Issuer>
  <samlp:NameIDPolicy
    Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    AllowCreate="true"/>
</samlp:AuthnRequest>`;
}

async function deflateRaw(str: string): Promise<string> {
  const encoded = encodeUtf8(str);
  const cs = new CompressionStream("deflate-raw");
  const writer = cs.writable.getWriter();
  writer.write(encoded);
  writer.close();

  const chunks: Uint8Array[] = [];
  const reader = cs.readable.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }

  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }

  return base64Encode(out);
}

export interface BuildSamlRedirectOptions {
  /** The AuthnRequest ID to use (must match the value bound into RelayState). */
  requestId: string;
  /** RelayState value to echo through the IdP (request binding). */
  relayState?: string;
}

export async function buildSamlRedirectUrl(
  config: SamlConfig,
  opts: BuildSamlRedirectOptions,
): Promise<string> {
  const issueInstant = new Date().toISOString();
  const xml = buildAuthnRequestXml(config, opts.requestId, issueInstant);

  const compressed = await deflateRaw(xml);

  const url = new URL(config.idpSsoUrl);
  url.searchParams.set("SAMLRequest", compressed);
  if (opts.relayState) url.searchParams.set("RelayState", opts.relayState);

  return url.toString();
}
