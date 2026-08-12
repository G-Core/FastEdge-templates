import { test } from "node:test";
import assert from "node:assert/strict";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import { SignedXml, Application } from "xmldsigjs";
import * as x509 from "@peculiar/x509";
import { validateSamlResponse } from "../../federation/saml/response.js";

// In StarlingMonkey (production) DOMParser/XMLSerializer are globals and
// xml-core uses them directly. Under Node they are absent, so register them as
// globals here — this hits xml-core's same global-first path used in prod and
// avoids wiring its transitive setNodeDependencies/xpath plumbing.
(globalThis as unknown as { DOMParser?: unknown }).DOMParser ??= DOMParser;
(globalThis as unknown as { XMLSerializer?: unknown }).XMLSerializer ??=
  XMLSerializer;

// xmldsigjs does not auto-init a crypto engine under Node (it detects "node
// plugin" and skips); @peculiar/x509 needs one too. Wire WebCrypto explicitly.
Application.setEngine("node", globalThis.crypto);
x509.cryptoProvider.set(globalThis.crypto);

const SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
const SIGN_ALG = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as const;
const KEYGEN_ALG = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
} as const;

const IDP_ENTITY_ID = "https://idp.example.com/metadata";
const SP_ENTITY_ID = "https://sp.example.com/saml";
const LEGIT_NAME_ID = "alice@example.com";
const ASSERTION_ID = "_assertion-1";

// One keypair + self-signed cert acts as "the IdP". A second, unrelated cert is
// used to prove signature verification rejects the wrong key.
const idpKeys = await globalThis.crypto.subtle.generateKey(KEYGEN_ALG, true, [
  "sign",
  "verify",
]);
const idpCert = await selfSignedPem(idpKeys);

const otherKeys = await globalThis.crypto.subtle.generateKey(KEYGEN_ALG, true, [
  "sign",
  "verify",
]);
const otherCert = await selfSignedPem(otherKeys);

async function selfSignedPem(keys: CryptoKeyPair): Promise<string> {
  const cert = await x509.X509CertificateGenerator.createSelfSigned(
    {
      serialNumber: "01",
      name: "CN=Test IdP",
      notBefore: new Date("2020-01-01T00:00:00Z"),
      notAfter: new Date("2100-01-01T00:00:00Z"),
      signingAlgorithm: SIGN_ALG,
      keys,
    },
    globalThis.crypto,
  );
  return cert.toString("pem");
}

interface AssertionOpts {
  nameId?: string;
  assertionId?: string;
  audience?: string;
  notBefore?: string;
  notOnOrAfter?: string;
  inResponseTo?: string;
}

function assertionXml(o: AssertionOpts = {}): string {
  const nameId = o.nameId ?? LEGIT_NAME_ID;
  const id = o.assertionId ?? ASSERTION_ID;
  const audience = o.audience ?? SP_ENTITY_ID;
  const notBefore = o.notBefore ?? "2020-01-01T00:00:00Z";
  const notOnOrAfter = o.notOnOrAfter ?? "2099-01-01T00:00:00Z";
  const irt = o.inResponseTo ? ` InResponseTo="${o.inResponseTo}"` : "";
  return `<saml:Assertion xmlns:saml="${SAML}" ID="${id}" Version="2.0" IssueInstant="2020-01-01T00:00:00Z">` +
    `<saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>` +
    `<saml:Subject><saml:NameID>${nameId}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
    `<saml:SubjectConfirmationData${irt} NotOnOrAfter="${notOnOrAfter}"/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">` +
    `<saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AttributeStatement>` +
    `<saml:Attribute Name="email"><saml:AttributeValue>${nameId}</saml:AttributeValue></saml:Attribute>` +
    `<saml:Attribute Name="role"><saml:AttributeValue>user</saml:AttributeValue></saml:Attribute>` +
    `</saml:AttributeStatement></saml:Assertion>`;
}

function responseXml(assertions: string): string {
  return `<?xml version="1.0"?>` +
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response-1" Version="2.0" IssueInstant="2020-01-01T00:00:00Z">` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    assertions +
    `</samlp:Response>`;
}

/**
 * Signs the element bearing `id` (enveloped) with the IdP key and inserts the
 * resulting <Signature> as that element's first child (so the enveloped
 * transform — which only strips direct-child signatures — can remove it).
 */
async function signElementById(
  xml: string,
  id: string,
  privateKey: CryptoKey,
): Promise<string> {
  const doc = new DOMParser().parseFromString(xml, "application/xml");
  const signedXml = new SignedXml();
  // Use exclusive c14n for the SignedInfo too (real IdPs do). Without this the
  // default inclusive c14n pulls in inherited samlp/saml namespaces only once
  // the signature is nested in the Response, breaking the round-trip.
  signedXml.XmlSignature.SignedInfo.CanonicalizationMethod.Algorithm =
    "http://www.w3.org/2001/10/xml-exc-c14n#";
  await signedXml.Sign(SIGN_ALG, privateKey, doc.documentElement as unknown as Element, {
    references: [
      { uri: `#${id}`, hash: "SHA-256", transforms: ["enveloped", "exc-c14n"] },
    ],
  });
  const sigEl = signedXml.GetXml();
  if (!sigEl) throw new Error("failed to produce signature element");
  const all = doc.getElementsByTagName("*");
  let target: Element | undefined;
  for (let i = 0; i < all.length; i++) {
    if (all[i].getAttribute("ID") === id || all[i].getAttribute("Id") === id) {
      target = all[i];
      break;
    }
  }
  if (!target) throw new Error(`no element with id ${id} to sign`);
  target.insertBefore(sigEl as unknown as Node, target.firstChild);
  return new XMLSerializer().serializeToString(doc);
}

/** Signs the assertion (the common case). */
function signResponse(
  xml: string,
  privateKey: CryptoKey,
  assertionId = ASSERTION_ID,
): Promise<string> {
  return signElementById(xml, assertionId, privateKey);
}

function b64(xml: string): string {
  return Buffer.from(xml, "utf8").toString("base64");
}

const config = {
  idpSsoUrl: "https://idp.example.com/sso",
  idpEntityId: IDP_ENTITY_ID,
  idpCert,
  spEntityId: SP_ENTITY_ID,
  spAcsUrl: "https://sp.example.com/acs",
  sessionSecret: "unused",
};

// --- Happy path ---
test("validateSamlResponse: valid signed assertion → claims extracted", async () => {
  const signed = await signResponse(responseXml(assertionXml()), idpKeys.privateKey);
  const claims = await validateSamlResponse(b64(signed), config);
  assert.equal(claims.nameId, LEGIT_NAME_ID);
  assert.equal(claims.attributes.email, LEGIT_NAME_ID);
  assert.equal(claims.attributes.role, "user");
});

test("validateSamlResponse: non-ASCII NameID/attribute survive UTF-8 decode", async () => {
  const nameId = "münchner.josé@example.com";
  const signed = await signResponse(responseXml(assertionXml({ nameId })), idpKeys.privateKey);
  const claims = await validateSamlResponse(b64(signed), config);
  assert.equal(claims.nameId, nameId);
  // assertionXml sets the `email` attribute to the same value — verifies an
  // attribute value (not just NameID) also decodes correctly.
  assert.equal(claims.attributes.email, nameId);
});

test("validateSamlResponse: InResponseTo extracted from signed SubjectConfirmationData", async () => {
  const signed = await signResponse(
    responseXml(assertionXml({ inResponseTo: "_req-abc123" })),
    idpKeys.privateKey,
  );
  const claims = await validateSamlResponse(b64(signed), config);
  assert.equal(claims.inResponseTo, "_req-abc123");
});

test("validateSamlResponse: InResponseTo absent → undefined (unsolicited)", async () => {
  const signed = await signResponse(responseXml(assertionXml()), idpKeys.privateKey);
  const claims = await validateSamlResponse(b64(signed), config);
  assert.equal(claims.inResponseTo, undefined);
});

// --- XML Signature Wrapping ---
test("validateSamlResponse: XSW — forged assertion prepended is rejected", async () => {
  // Sign a legitimate assertion, then inject a forged assertion (admin
  // identity, unsigned) before it. The old code read NameID[0] globally and
  // would return the forgery; binding + single-assertion enforcement rejects it.
  const signed = await signResponse(responseXml(assertionXml()), idpKeys.privateKey);
  const forged = assertionXml({ nameId: "admin@evil.com", assertionId: "_forged" });
  // Insert the forged assertion as the first child after <Status>.
  const wrapped = signed.replace(
    /(<\/samlp:Status>)/,
    `$1${forged}`,
  );
  await assert.rejects(
    () => validateSamlResponse(b64(wrapped), config),
    /exactly one SAML Assertion|signature wrapping|exactly one XML signature/i,
  );
});

test("validateSamlResponse: XSW — forged assertion appended is rejected", async () => {
  const signed = await signResponse(responseXml(assertionXml()), idpKeys.privateKey);
  const forged = assertionXml({ nameId: "admin@evil.com", assertionId: "_forged" });
  const wrapped = signed.replace(/(<\/samlp:Response>)/, `${forged}$1`);
  await assert.rejects(
    () => validateSamlResponse(b64(wrapped), config),
    /exactly one SAML Assertion|signature wrapping/i,
  );
});

test("validateSamlResponse: XSW — valid signature over decoy, assertion outside signed subtree → rejected", async () => {
  // A validly-signed but non-assertion element (the decoy) sits next to a single
  // forged assertion that is NOT a descendant of it. The signature verifies and
  // there is exactly one Assertion, so only the subtree-containment binding can
  // catch this — exactly the case the binding exists for.
  const decoy = `<samlp:Extensions xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_decoy"><note>signed-but-not-the-assertion</note></samlp:Extensions>`;
  const forged = assertionXml({ nameId: "admin@evil.com" });
  const xml = `<?xml version="1.0"?>` +
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_response-1" Version="2.0" IssueInstant="2020-01-01T00:00:00Z">` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    decoy + forged +
    `</samlp:Response>`;
  const signed = await signElementById(xml, "_decoy", idpKeys.privateKey);
  await assert.rejects(
    () => validateSamlResponse(b64(signed), config),
    /not covered by the verified signature|signature wrapping/i,
  );
});

// --- Tampering ---
test("validateSamlResponse: tampered NameID after signing → rejected", async () => {
  const signed = await signResponse(responseXml(assertionXml()), idpKeys.privateKey);
  const tampered = signed.replace(LEGIT_NAME_ID, "attacker@evil.com");
  await assert.rejects(
    () => validateSamlResponse(b64(tampered), config),
    /signature verification failed/i,
  );
});

// --- Weak algorithm downgrade (SHA-1) ---
test("validateSamlResponse: SHA-1 SignatureMethod → rejected before verification", async () => {
  const signed = await signResponse(responseXml(assertionXml()), idpKeys.privateKey);
  // Downgrade only the advertised SignatureMethod to RSA-SHA1. The guard runs
  // before signature verification, so this is rejected on the algorithm alone.
  const downgraded = signed.replace(
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
  );
  await assert.rejects(
    () => validateSamlResponse(b64(downgraded), config),
    /weak SignatureMethod/i,
  );
});

test("validateSamlResponse: SHA-1 DigestMethod → rejected before verification", async () => {
  const signed = await signResponse(responseXml(assertionXml()), idpKeys.privateKey);
  const downgraded = signed.replace(
    "http://www.w3.org/2001/04/xmlenc#sha256",
    "http://www.w3.org/2000/09/xmldsig#sha1",
  );
  await assert.rejects(
    () => validateSamlResponse(b64(downgraded), config),
    /weak DigestMethod/i,
  );
});

// --- Missing signature ---
test("validateSamlResponse: no signature → rejected", async () => {
  const unsigned = responseXml(assertionXml());
  await assert.rejects(
    () => validateSamlResponse(b64(unsigned), config),
    /No XML signature/i,
  );
});

// --- Wrong signing key ---
test("validateSamlResponse: signed by wrong key → rejected", async () => {
  const signed = await signResponse(responseXml(assertionXml()), otherKeys.privateKey);
  await assert.rejects(
    () => validateSamlResponse(b64(signed), config),
    /signature verification failed/i,
  );
});

// --- Time window ---
test("validateSamlResponse: expired Conditions window → rejected", async () => {
  const signed = await signResponse(
    responseXml(assertionXml({ notOnOrAfter: "2020-06-01T00:00:00Z" })),
    idpKeys.privateKey,
  );
  await assert.rejects(
    () => validateSamlResponse(b64(signed), config),
    /expired/i,
  );
});

// --- Audience ---
test("validateSamlResponse: audience mismatch → rejected", async () => {
  const signed = await signResponse(
    responseXml(assertionXml({ audience: "https://wrong-sp.example.com" })),
    idpKeys.privateKey,
  );
  await assert.rejects(
    () => validateSamlResponse(b64(signed), config),
    /Audience mismatch/i,
  );
});

// --- Issuer (uses the wrong cert's identity won't matter; tests Issuer check) ---
test("validateSamlResponse: unexpected Issuer → rejected", async () => {
  const xml = responseXml(
    assertionXml().replace(IDP_ENTITY_ID, "https://evil-idp.example.com"),
  );
  // Re-sign so the signature is valid but Issuer is wrong.
  const signed = await signResponse(xml, idpKeys.privateKey);
  await assert.rejects(
    () => validateSamlResponse(b64(signed), config),
    /Unexpected Issuer/i,
  );
});

// --- StarlingMonkey exportKey polyfill ---
// crypto.subtle.exportKey is not implemented in StarlingMonkey. response.ts
// installs a polyfill at module load time when exportKey is absent, and always
// registers SPKI bytes via spkiByKey.set() after importKey. This test simulates
// the StarlingMonkey environment by replacing importKey/exportKey at runtime and
// verifying the full validation path still works end-to-end.
test("validateSamlResponse: works when exportKey unavailable (StarlingMonkey polyfill)", async () => {
  type SubtleAny = Record<string, unknown>;
  const subtleAny = crypto.subtle as unknown as SubtleAny;
  const origExportKey = subtleAny.exportKey;
  const origImportKey = crypto.subtle.importKey.bind(crypto.subtle);

  // Track SPKI bytes for each key imported under "spki" format.
  const spkiStore = new WeakMap<CryptoKey, ArrayBuffer>();

  subtleAny.importKey = async (
    format: unknown,
    keyData: unknown,
    algorithm: unknown,
    extractable: unknown,
    keyUsages: unknown,
  ) => {
    const key = await origImportKey(
      format as Parameters<typeof origImportKey>[0],
      keyData as Parameters<typeof origImportKey>[1],
      algorithm as Parameters<typeof origImportKey>[2],
      extractable as boolean,
      keyUsages as KeyUsage[],
    );
    if (format === "spki") spkiStore.set(key, keyData as ArrayBuffer);
    return key;
  };

  subtleAny.exportKey = async (format: unknown, key: unknown): Promise<ArrayBuffer> => {
    if (format === "spki") {
      const spki = spkiStore.get(key as CryptoKey);
      if (spki) return spki;
    }
    throw new Error("exportKey not available");
  };

  try {
    const signed = await signResponse(responseXml(assertionXml()), idpKeys.privateKey);
    const claims = await validateSamlResponse(b64(signed), config);
    assert.equal(claims.nameId, LEGIT_NAME_ID);
  } finally {
    subtleAny.exportKey = origExportKey;
    subtleAny.importKey = origImportKey;
  }
});
