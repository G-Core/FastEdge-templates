import { DOMParser } from "@xmldom/xmldom";
import { SignedXml } from "xmldsigjs";
import { X509Certificate } from "@peculiar/x509";
import { SamlConfig } from "./config.js";
import { base64Decode } from "../../util/bytes";

// StarlingMonkey does not implement crypto.subtle.exportKey. xmldsigjs calls
// exportKey inside reimportKey() during Verify(). Polyfill: register SPKI bytes
// when we import each key, return them when exportKey("spki", key) is called.
const spkiByKey = new WeakMap<CryptoKey, ArrayBuffer>();
if (typeof (crypto.subtle as unknown as Record<string, unknown>).exportKey !== "function") {
  (crypto.subtle as unknown as Record<string, unknown>).exportKey = async (
    format: string,
    key: CryptoKey,
  ): Promise<ArrayBuffer> => {
    if (format === "spki") {
      const spki = spkiByKey.get(key);
      if (spki) return spki;
    }
    throw new Error(`exportKey polyfill: format="${format}" not supported or key not registered`);
  };
}

export interface SamlAttributes {
  [key: string]: string | string[];
}

export interface SamlClaims {
  nameId: string;
  attributes: SamlAttributes;
  /**
   * `InResponseTo` read from the signed `SubjectConfirmationData` — the ID of
   * the AuthnRequest this assertion answers (request binding). `undefined`
   * for IdP-initiated (unsolicited) responses.
   */
  inResponseTo?: string;
}

const SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const XMLDSIG = "http://www.w3.org/2000/09/xmldsig#";

// The IdP cert is imported as RSASSA-PKCS1-v1_5 / SHA-256, so only the RSA-SHA256
// signature method and SHA-256 digest can ever verify. Pin them explicitly: a
// SHA-1 (or other legacy) SignatureMethod/DigestMethod in the response is a
// downgrade attempt and is rejected before we even attempt verification, rather
// than relying on xmldsigjs's algorithm selection to fail safely.
const ALLOWED_SIGNATURE_METHODS = new Set([
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
]);
const ALLOWED_DIGEST_METHODS = new Set([
  "http://www.w3.org/2001/04/xmlenc#sha256",
]);

function assertStrongAlgorithms(sigEl: Element): void {
  const sigMethod =
    sigEl.getElementsByTagNameNS(XMLDSIG, "SignatureMethod")[0]?.getAttribute(
      "Algorithm",
    ) ?? "";
  if (!ALLOWED_SIGNATURE_METHODS.has(sigMethod)) {
    throw new Error(`Unsupported or weak SignatureMethod: ${sigMethod || "<none>"}`);
  }
  const digestEls = sigEl.getElementsByTagNameNS(XMLDSIG, "DigestMethod");
  if (digestEls.length === 0) {
    throw new Error("No DigestMethod found in signature");
  }
  for (let i = 0; i < digestEls.length; i++) {
    const alg = digestEls[i].getAttribute("Algorithm") ?? "";
    if (!ALLOWED_DIGEST_METHODS.has(alg)) {
      throw new Error(`Unsupported or weak DigestMethod: ${alg || "<none>"}`);
    }
  }
}

function normalizePem(pemOrBase64: string): string {
  const trimmed = pemOrBase64.trim();
  if (trimmed.startsWith("-----BEGIN")) return trimmed;
  // Wrap bare base64 in PEM headers
  const lines = trimmed.match(/.{1,64}/g)?.join("\n") ?? trimmed;
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
}

function stripComments(xml: string): string {
  return xml.replace(/<!--[\s\S]*?-->/g, "");
}

function parseDate(dateStr: string | null): Date | null {
  if (!dateStr) return null;
  const d = new Date(dateStr);
  return isNaN(d.getTime()) ? null : d;
}

/**
 * Finds elements carrying an ID attribute equal to `id`, excluding any element
 * inside a ds:Signature subtree. Mirrors xmldsigjs's own reference-resolution
 * scan (Id/ID/id, signatures excluded) so the element we bind claims to is the
 * exact element whose digest the library verified.
 */
function findById(root: Element, id: string): Element[] {
  const out: Element[] = [];
  const walk = (el: Element) => {
    if (
      el.namespaceURI === XMLDSIG &&
      (el.localName || el.nodeName) === "Signature"
    ) {
      return; // never resolve a reference into the signature's own subtree
    }
    for (const attrName of ["Id", "ID", "id"]) {
      if (el.hasAttribute(attrName) && el.getAttribute(attrName) === id) {
        out.push(el);
        break;
      }
    }
    const kids = el.childNodes;
    for (let i = 0; i < kids.length; i++) {
      const child = kids[i];
      if (child && child.nodeType === 1) walk(child as unknown as Element);
    }
  };
  walk(root);
  return out;
}

/** True if `node` is `ancestor` or a descendant of it. */
function isWithin(ancestor: Node, node: Node): boolean {
  let cur: Node | null = node;
  while (cur) {
    if (cur === ancestor) return true;
    cur = cur.parentNode;
  }
  return false;
}

export async function validateSamlResponse(
  samlResponseB64: string,
  config: SamlConfig
): Promise<SamlClaims> {
  // 1. Decode base64 → bytes → UTF-8. atob() alone yields a latin1 byte-string,
  //    which corrupts non-ASCII names/emails in the assertion; decode the bytes
  //    as UTF-8 so international identities survive intact.
  const bytes = base64Decode(samlResponseB64);
  const decoded = new TextDecoder("utf-8").decode(bytes);

  // 2. Strip XML comments before any processing (CVE-2025-29775 / SAMLStorm mitigation)
  const safeXml = stripComments(decoded);

  // 3. Parse XML
  const parser = new DOMParser();
  const doc = parser.parseFromString(safeXml, "application/xml");

  // 4. Check StatusCode (lives on the Response, outside any Assertion; not
  //    identity-bearing, so a global read is acceptable — a forged Success
  //    status still cannot mint identity without a signed assertion below).
  const statusCodeEl = doc.getElementsByTagNameNS(SAMLP, "StatusCode")[0];
  const statusCode = statusCodeEl?.getAttribute("Value") ?? "";
  if (statusCode !== "urn:oasis:names:tc:SAML:2.0:status:Success") {
    throw new Error(`SAML authentication failed: ${statusCode}`);
  }

  // 5. Verify XMLDSig.
  //    XML Signature Wrapping defense: require EXACTLY ONE signature.
  //    Multiple signatures make "which element did we verify" ambiguous and are
  //    a wrapping vector; a single-IdP SP only ever needs one.
  const sigElements = doc.getElementsByTagNameNS(XMLDSIG, "Signature");
  if (sigElements.length === 0) {
    throw new Error("No XML signature found in SAMLResponse");
  }
  if (sigElements.length !== 1) {
    throw new Error(
      `Expected exactly one XML signature, found ${sigElements.length}`,
    );
  }
  const sigEl = sigElements[0];

  // Reject weak/legacy signature & digest algorithms (SHA-1 downgrade) before
  // attempting verification.
  assertStrongAlgorithms(sigEl);

  const pem = normalizePem(config.idpCert);
  const cert = new X509Certificate(pem);
  // Import through the global crypto (not @peculiar/webcrypto) so xmldsigjs
  // can use this key. Register SPKI bytes for the exportKey polyfill above.
  const spkiBytes = cert.publicKey.rawData;
  const publicKey = await crypto.subtle.importKey(
    "spki",
    spkiBytes,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true,
    ["verify"],
  );
  spkiByKey.set(publicKey, spkiBytes);

  const signedXml = new SignedXml(doc as unknown as Document);
  signedXml.LoadXml(sigEl as unknown as Element);

  // xmldsigjs reports failure two ways: it returns false (bad SignatureValue),
  // or it throws (e.g. a digest mismatch when the signed content was tampered).
  // Treat both as a failed signature so the caller sees one consistent error
  // and no raw library detail leaks out.
  let valid = false;
  try {
    valid = await signedXml.Verify(publicKey);
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new Error("XML signature verification failed");
  }

  // 5b. Bind extraction to the verified subtree.
  //     The signature proves SOME element is intact and IdP-signed, but says
  //     nothing about which element we read claims from. Resolve the signature's
  //     Reference to its target element, then require the identity we extract to
  //     live INSIDE that verified subtree. Without this binding an attacker can
  //     wrap one validly-signed assertion around a forged one and have us read
  //     the forgery (full authentication bypass).
  const refEls = sigEl.getElementsByTagNameNS(XMLDSIG, "Reference");
  if (refEls.length !== 1) {
    throw new Error(
      `Expected exactly one signature Reference, found ${refEls.length}`,
    );
  }
  const refUri = (refEls[0].getAttribute("URI") ?? "").trim();

  let signedEl: Element;
  if (refUri === "") {
    // Whole-document signature: any tampering changes the digest, so the entire
    // tree is the verified subtree.
    signedEl = doc.documentElement as unknown as Element;
  } else if (refUri.startsWith("#")) {
    const id = refUri.slice(1);
    const matches = findById(doc.documentElement as unknown as Element, id);
    // xmldsigjs already rejects duplicate IDs during Verify; we re-check in our
    // own DOM so the element we bind to is unambiguously the verified one.
    if (matches.length !== 1) {
      throw new Error(
        `Signature reference '#${id}' resolves to ${matches.length} elements`,
      );
    }
    signedEl = matches[0];
  } else {
    throw new Error(`Unsupported signature reference URI: ${refUri}`);
  }

  // 6. Require EXACTLY ONE Assertion, and require it to sit within the verified
  //    subtree. Together these defeat wrapping: a forged assertion is either a
  //    second Assertion (rejected here) or, to be the only one, would have to
  //    replace the signed content (which breaks the digest in step 5).
  const assertionEls = doc.getElementsByTagNameNS(SAML, "Assertion");
  if (assertionEls.length !== 1) {
    throw new Error(
      `Expected exactly one SAML Assertion, found ${assertionEls.length}`,
    );
  }
  const assertion = assertionEls[0];
  if (!isWithin(signedEl as unknown as Node, assertion as unknown as Node)) {
    throw new Error(
      "SAML Assertion is not covered by the verified signature (possible signature wrapping)",
    );
  }

  // From here every claim is read from WITHIN the verified `assertion` element,
  // never globally (so a Response-level Issuer/etc. can no longer shadow the
  // Assertion's).

  // 7. Validate Issuer (the Assertion's own Issuer)
  const issuerEl = assertion.getElementsByTagNameNS(SAML, "Issuer")[0];
  const issuer = issuerEl?.textContent?.trim();
  if (issuer !== config.idpEntityId) {
    throw new Error(`Unexpected Issuer: ${issuer}`);
  }

  // 8. Validate AudienceRestriction
  const audienceEls = assertion.getElementsByTagNameNS(SAML, "Audience");
  const audiences = Array.from({ length: audienceEls.length }, (_, i) =>
    audienceEls[i].textContent?.trim()
  );
  if (!audiences.includes(config.spEntityId)) {
    throw new Error(`Audience mismatch. Expected ${config.spEntityId}, got: ${audiences.join(", ")}`);
  }

  // 9. Validate Conditions time window (±30s clock skew)
  const conditionsEl = assertion.getElementsByTagNameNS(SAML, "Conditions")[0];
  const now = Date.now();
  const skew = 30_000;

  const notBefore = parseDate(conditionsEl?.getAttribute("NotBefore") ?? null);
  const notOnOrAfter = parseDate(conditionsEl?.getAttribute("NotOnOrAfter") ?? null);

  if (notBefore && now < notBefore.getTime() - skew) {
    throw new Error("SAML assertion is not yet valid (NotBefore)");
  }
  if (notOnOrAfter && now > notOnOrAfter.getTime() + skew) {
    throw new Error("SAML assertion has expired (NotOnOrAfter)");
  }

  // 10. Validate SubjectConfirmationData
  const scdEl = assertion.getElementsByTagNameNS(SAML, "SubjectConfirmationData")[0];
  const scdNotOnOrAfter = parseDate(scdEl?.getAttribute("NotOnOrAfter") ?? null);
  if (scdNotOnOrAfter && now > scdNotOnOrAfter.getTime() + skew) {
    throw new Error("SAML SubjectConfirmationData has expired");
  }
  // InResponseTo from the signed SubjectConfirmationData (request binding).
  const inResponseTo = scdEl?.getAttribute("InResponseTo")?.trim() || undefined;

  // 11. Extract NameID
  const nameIdEl = assertion.getElementsByTagNameNS(SAML, "NameID")[0];
  const nameId = nameIdEl?.textContent?.trim();
  if (!nameId) {
    throw new Error("NameID not found in SAML assertion");
  }

  // 12. Extract attributes
  const attributes: SamlAttributes = {};
  const attrEls = assertion.getElementsByTagNameNS(SAML, "Attribute");
  for (let i = 0; i < attrEls.length; i++) {
    const attr = attrEls[i];
    const name = attr.getAttribute("Name") ?? attr.getAttribute("FriendlyName") ?? "";
    if (!name) continue;
    const values: string[] = [];
    const valueEls = attr.getElementsByTagNameNS(SAML, "AttributeValue");
    for (let j = 0; j < valueEls.length; j++) {
      const text = valueEls[j].textContent?.trim();
      if (text) values.push(text);
    }
    attributes[name] = values.length === 1 ? values[0] : values;
  }

  return { nameId, attributes, inResponseTo };
}
