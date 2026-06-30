import { Hono } from "hono";
import type { Context } from "hono";
import { getCookie } from "hono/cookie";
import { getEnv } from "fastedge::env";
import { Cache } from "fastedge::cache";
import { loadConfig, loadSecrets } from "./config.js";
import type { Config, Secrets } from "./config.js";
import {
  verifyHandoffTicket,
  signMfaSession,
  signProof,
  signEnrollCookie,
  verifyEnrollCookie,
  buildJwks,
  importEs256PrivateKey,
  ticketFingerprint,
} from "./lib/jwt.js";
import { findMatchingStep, generateSecret, otpauthUri } from "./lib/totp.js";
import { timingSafeEqual } from "./lib/safeEqual.js";
import { otpauthToSvg } from "./lib/qr.js";
import { appendCookie } from "./lib/cookies.js";
import { readSeed, writeSeed, isEnrolled } from "./seed/kv.js";
import { validateRedirect } from "./lib/validate.js";
import { renderChallengePage } from "./challenge.js";
import { renderEnrollPage } from "./enroll.js";

// Issue the edge MFA cookies after a successful OTP: the HS256 mfa_session the
// Rust filter checks, plus (Profile B) a one-time ES256 proof for origins that
// verify via JWKS. Shared by /verify and /activate so the two success paths
// can't drift. Caller must ensure secrets.mfaSessionKey is set.
async function setMfaCookies(
  c: Context,
  cfg: Config,
  secrets: Secrets,
  userId: string,
  logTag: string,
): Promise<void> {
  const claimOpts = {
    ...(cfg.mfaAudience ? { aud: cfg.mfaAudience } : {}),
    ...(cfg.mfaIssuer ? { iss: cfg.mfaIssuer } : {}),
  };
  const sessionToken = await signMfaSession(
    userId,
    secrets.mfaSessionKey as string,
    cfg.mfaSessionTtl,
    claimOpts,
  );
  appendCookie(c, cfg.mfaSessionCookie, sessionToken, {
    maxAge: cfg.mfaSessionTtl,
  });

  // Profile B: mint a one-time ES256 proof if a signing key is configured.
  // Delivered as a short-lived cookie — never in a URL. A signing failure is
  // non-fatal: the Profile A session cookie above still stands.
  if (secrets.mfaProofSigningKey) {
    try {
      const privateKey = await importEs256PrivateKey(secrets.mfaProofSigningKey);
      const jti = crypto.randomUUID();
      const proof = await signProof(userId, privateKey, cfg.proofTtl, jti, claimOpts);
      appendCookie(c, cfg.mfaProofCookie, proof, { maxAge: cfg.proofTtl });
    } catch (err) {
      console.error(`[${logTag}] Profile B proof signing failed: ${err}`);
    }
  }
}

function buildApp(authPrefix: string): Hono {
  const app = new Hono();

  // --- Health ---
  app.get("/health", (c) => c.json({ ok: true }));

  // --- Enroll: POST {prefix}/enroll ---
  app.post(`${authPrefix}/enroll`, async (c) => {
    const cfg = loadConfig();
    const secrets = loadSecrets();

    const authHeader = c.req.header("authorization") ?? "";
    const key = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7)
      : authHeader;
    // Constant-time compare so a timing oracle can't be used to recover the
    // enroll API key character by character.
    if (!secrets.enrollApiKey || !timingSafeEqual(key, secrets.enrollApiKey)) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const body = (await c.req.json().catch(() => null)) as Record<
      string,
      unknown
    > | null;
    if (!body || typeof body.userId !== "string" || !body.userId) {
      return c.json({ error: "userId required" }, 400);
    }
    const userId = body.userId as string;
    const account = typeof body.account === "string" ? body.account : userId;
    const force = body.force === true;

    if (!cfg.kvStoreName)
      return c.json({ error: "KV_STORE_NAME not configured" }, 503);
    if (!cfg.kvStoreId)
      return c.json({ error: "KV_STORE_ID not configured" }, 503);
    if (!secrets.gcoreApiToken)
      return c.json({ error: "GCORE_API_TOKEN not configured" }, 503);

    // Guard against silent re-enrollment
    if (!force && isEnrolled(cfg.kvStoreName, userId, cfg.kvKeyPrefix)) {
      return c.json(
        { error: "Already enrolled. Set force:true to re-enroll." },
        409,
      );
    }

    const seed = await generateSecret();
    const uri = otpauthUri(seed, account, cfg.issuer, {
      digits: cfg.digits,
      period: cfg.period,
      algorithm: cfg.algorithm,
    });
    const svgQr = otpauthToSvg(uri);

    try {
      await writeSeed(
        cfg.gcoreApiUrl,
        secrets.gcoreApiToken,
        cfg.kvStoreId,
        userId,
        seed,
        cfg.kvKeyPrefix,
      );
    } catch (err) {
      return c.json({ error: `KV write failed: ${err}` }, 502);
    }

    return c.json({ userId, otpauthUri: uri, svgQr });
  });

  // --- Challenge page: GET {prefix}/challenge?t= ---
  app.get(`${authPrefix}/challenge`, async (c) => {
    const cfg = loadConfig();
    const secrets = loadSecrets();
    const ticket = c.req.query("t");
    const error = c.req.query("error");

    if (!ticket) return c.text("Missing ticket", 400);
    if (!secrets.handoffKey) return c.text("HANDOFF_KEY not configured", 503);

    const claims = await verifyHandoffTicket(ticket, secrets.handoffKey);
    if (!claims) return c.text("Invalid or expired ticket", 400);

    // Not enrolled: send to self-service activation, or refuse when self-service
    // enrollment is disabled (admin-provisioned deployments).
    if (cfg.kvStoreName && !isEnrolled(cfg.kvStoreName, claims.sub, cfg.kvKeyPrefix)) {
      if (!cfg.allowSelfEnrollment) {
        return c.text("Not enrolled. Please contact your administrator.", 403);
      }
      return c.redirect(
        `${authPrefix}/activate?t=${encodeURIComponent(ticket)}`,
        303,
      );
    }

    return c.html(
      renderChallengePage({
        formAction: `${authPrefix}/verify`,
        ticket,
        error: error ?? undefined,
        digits: cfg.digits,
        brandName: cfg.brandName,
        brandLogoUrl: cfg.brandLogoUrl,
        brandFaviconUrl: cfg.brandFaviconUrl,
        brandButtonColor: cfg.brandButtonColor,
        brandButtonHoverColor: cfg.brandButtonHoverColor,
      }),
    );
  });

  // --- Self-service enrollment: GET {prefix}/activate?t= ---
  // Generates a new TOTP seed, shows QR code, stores seed in a signed
  // HttpOnly cookie (not written to KV until the user confirms the code).
  app.get(`${authPrefix}/activate`, async (c) => {
    const cfg = loadConfig();
    const secrets = loadSecrets();
    if (!cfg.allowSelfEnrollment)
      return c.text("Self-service enrollment is disabled.", 403);
    const ticket = c.req.query("t");

    if (!ticket) return c.text("Missing ticket", 400);
    if (!secrets.handoffKey) return c.text("HANDOFF_KEY not configured", 503);

    const claims = await verifyHandoffTicket(ticket, secrets.handoffKey);
    if (!claims) return c.text("Invalid or expired ticket", 400);

    // Already enrolled → skip to challenge
    if (cfg.kvStoreName && isEnrolled(cfg.kvStoreName, claims.sub, cfg.kvKeyPrefix)) {
      return c.redirect(
        `${authPrefix}/challenge?t=${encodeURIComponent(ticket)}`,
        303,
      );
    }

    const seed = await generateSecret();
    const uri = otpauthUri(seed, claims.sub, cfg.issuer, {
      digits: cfg.digits,
      period: cfg.period,
      algorithm: cfg.algorithm,
    });
    const svgQr = otpauthToSvg(uri);

    // Store seed in a signed cookie — written to KV only after confirmation
    const enrollToken = await signEnrollCookie(
      claims.sub,
      seed,
      claims.next,
      secrets.handoffKey,
      cfg.enrollTtl,
    );
    appendCookie(c, "totp_enroll", enrollToken, { maxAge: cfg.enrollTtl });

    return c.html(
      renderEnrollPage({
        formAction: `${authPrefix}/activate`,
        svgQr,
        digits: cfg.digits,
        brandName: cfg.brandName,
        brandLogoUrl: cfg.brandLogoUrl,
        brandFaviconUrl: cfg.brandFaviconUrl,
        brandButtonColor: cfg.brandButtonColor,
        brandButtonHoverColor: cfg.brandButtonHoverColor,
      }),
    );
  });

  // --- Self-service enrollment confirm: POST {prefix}/activate ---
  // Verifies the confirmation code, writes seed to KV, issues mfa_session.
  app.post(`${authPrefix}/activate`, async (c) => {
    const cfg = loadConfig();
    const secrets = loadSecrets();

    if (!cfg.allowSelfEnrollment)
      return c.text("Self-service enrollment is disabled.", 403);
    if (!secrets.handoffKey) return c.text("HANDOFF_KEY not configured", 503);

    const enrollToken = getCookie(c, "totp_enroll");
    if (!enrollToken)
      return c.text(
        "Enrollment session missing or expired — please log in again",
        400,
      );

    const enrollClaims = await verifyEnrollCookie(
      enrollToken,
      secrets.handoffKey,
    );
    if (!enrollClaims)
      return c.text(
        "Enrollment session missing or expired — please log in again",
        400,
      );

    const { sub: userId, seed, next } = enrollClaims;

    // The enroll page submits the code as JSON via fetch(); a urlencoded
    // fallback covers no-JS / direct posts.
    const contentType = c.req.header("content-type") ?? "";
    const wantsJson = contentType.includes("application/json");
    let code = "";
    if (wantsJson) {
      const parsed = (await c.req.json().catch(() => ({}))) as {
        code?: unknown;
      };
      code =
        typeof parsed.code === "string" ? parsed.code.replace(/\s/g, "") : "";
    } else {
      const params = new URLSearchParams(await c.req.text().catch(() => ""));
      code = (params.get("code") ?? "").replace(/\s/g, "");
    }

    // Verify the confirmation code against the pending seed
    const matchedStep = await findMatchingStep(code, seed, {
      digits: cfg.digits,
      period: cfg.period,
      algorithm: cfg.algorithm,
      drift: cfg.drift,
    });

    if (matchedStep === null) {
      if (wantsJson) {
        return c.json({ message: "Incorrect code — please try again." }, 400);
      }
      const uri = otpauthUri(seed, userId, cfg.issuer, {
        digits: cfg.digits,
        period: cfg.period,
        algorithm: cfg.algorithm,
      });
      return c.html(
        renderEnrollPage({
          formAction: `${authPrefix}/activate`,
          svgQr: otpauthToSvg(uri),
          error: "invalid",
          digits: cfg.digits,
          brandName: cfg.brandName,
          brandLogoUrl: cfg.brandLogoUrl,
          brandFaviconUrl: cfg.brandFaviconUrl,
          brandButtonColor: cfg.brandButtonColor,
          brandButtonHoverColor: cfg.brandButtonHoverColor,
        }),
      );
    }

    // Code confirmed — persist seed to KV
    if (!cfg.kvStoreName) return c.text("KV_STORE_NAME not configured", 503);
    if (!cfg.kvStoreId) return c.text("KV_STORE_ID not configured", 503);
    if (!secrets.gcoreApiToken)
      return c.text("GCORE_API_TOKEN not configured", 503);

    try {
      await writeSeed(
        cfg.gcoreApiUrl,
        secrets.gcoreApiToken,
        cfg.kvStoreId,
        userId,
        seed,
        cfg.kvKeyPrefix,
      );
    } catch (err) {
      console.error(`[activate] KV write failed: ${err}`);
      if (wantsJson) {
        return c.json(
          { message: "Enrollment could not be saved. Please try again." },
          503,
        );
      }
      const uri = otpauthUri(seed, userId, cfg.issuer, {
        digits: cfg.digits,
        period: cfg.period,
        algorithm: cfg.algorithm,
      });
      return c.html(
        renderEnrollPage({
          formAction: `${authPrefix}/activate`,
          svgQr: otpauthToSvg(uri),
          error: "kv",
          digits: cfg.digits,
          brandName: cfg.brandName,
          brandLogoUrl: cfg.brandLogoUrl,
          brandFaviconUrl: cfg.brandFaviconUrl,
          brandButtonColor: cfg.brandButtonColor,
          brandButtonHoverColor: cfg.brandButtonHoverColor,
        }),
        503,
      );
    }

    // Clear enrollment cookie
    appendCookie(c, "totp_enroll", "", { maxAge: 0 });

    // Issue mfa_session + optional Profile B proof (same as /verify)
    if (!secrets.mfaSessionKey)
      return c.text("MFA_SESSION_KEY not configured", 503);
    await setMfaCookies(c, cfg, secrets, userId, "activate");

    const target = validateRedirect(next);
    // JSON path: the page's fetch() can't navigate the top window via a 303,
    // so hand it the destination to navigate to. The mfa_session cookie set
    // above rides along on this response. Fallback form posts get the 303.
    if (wantsJson) {
      return c.json({ next: target });
    }
    return c.redirect(target, 303);
  });

  // --- Verify: POST {prefix}/verify ---
  app.post(`${authPrefix}/verify`, async (c) => {
    const cfg = loadConfig();
    const secrets = loadSecrets();
    const branding = {
      digits: cfg.digits,
      brandName: cfg.brandName,
      brandLogoUrl: cfg.brandLogoUrl,
      brandFaviconUrl: cfg.brandFaviconUrl,
      brandButtonColor: cfg.brandButtonColor,
      brandButtonHoverColor: cfg.brandButtonHoverColor,
    };

    // Accept both form and JSON
    let ticket: string;
    let code: string;
    const ct = c.req.header("content-type") ?? "";
    if (ct.includes("application/json")) {
      const body = (await c.req.json().catch(() => ({}))) as Record<
        string,
        unknown
      >;
      ticket = String(body.t ?? "");
      code = String(body.code ?? "");
    } else {
      const params = new URLSearchParams(await c.req.text().catch(() => ""));
      ticket = params.get("t") ?? "";
      code = params.get("code") ?? "";
    }

    if (!ticket || !code) return c.text("Missing t or code", 400);
    if (!secrets.handoffKey) return c.text("HANDOFF_KEY not configured", 503);

    const claims = await verifyHandoffTicket(ticket, secrets.handoffKey);
    if (!claims) {
      return c.html(
        renderChallengePage({
          formAction: `${authPrefix}/verify`,
          ticket,
          error: "expired",
          ...branding,
        }),
        400,
      );
    }
    const { sub: userId, next } = claims;

    // SEC: single-use handoff ticket. The ticket is consumed on the first
    // successful verify (marked below); presenting it again — a replay of the
    // URL after a completed login — is refused here. POP-local best-effort,
    // like the replay/brute-force guards (see R1/R2).
    const ticketKey = `ticket:${await ticketFingerprint(ticket)}`;
    if (await Cache.exists(ticketKey)) {
      return c.html(
        renderChallengePage({
          formAction: `${authPrefix}/verify`,
          ticket,
          error: "expired",
          ...branding,
        }),
        400,
      );
    }

    // Brute-force guard (POP-local; see R2)
    const failKey = `fail:${userId}`;
    const attempts = await Cache.incr(failKey);
    if (attempts === 1) await Cache.expire(failKey, { ttl: 300 }); // 5-min window
    if (attempts > cfg.maxAttempts) {
      return c.html(
        renderChallengePage({
          formAction: `${authPrefix}/verify`,
          ticket,
          error: "locked",
          ...branding,
        }),
        429,
      );
    }

    if (!cfg.kvStoreName) return c.text("KV_STORE_NAME not configured", 503);
    const seed = readSeed(cfg.kvStoreName, userId, cfg.kvKeyPrefix);
    if (!seed) return c.json({ error: "User not enrolled" }, 403);

    // Find which time-step matched, then check POP-local replay guard
    const matchedStep = await findMatchingStep(code, seed, {
      digits: cfg.digits,
      period: cfg.period,
      algorithm: cfg.algorithm,
      drift: cfg.drift,
    });

    if (matchedStep === null) {
      return c.html(
        renderChallengePage({
          formAction: `${authPrefix}/verify`,
          ticket,
          error: "invalid",
          ...branding,
        }),
        200,
      );
    }

    // Mark step used atomically (TTL covers the full drift acceptance window).
    // incr is atomic, so two concurrent requests presenting the same valid code
    // race here and exactly one wins (count === 1) — a plain exists()-then-set()
    // check has a TOCTOU window that lets both through.
    const replayKey = `used:${userId}:${matchedStep}`;
    const replayTtl = cfg.period * (cfg.drift * 2 + 2);
    const replayCount = await Cache.incr(replayKey);
    if (replayCount === 1) {
      await Cache.expire(replayKey, { ttl: replayTtl });
    } else {
      return c.html(
        renderChallengePage({
          formAction: `${authPrefix}/verify`,
          ticket,
          error: "invalid",
          ...branding,
        }),
        200,
      );
    }

    // A valid, non-replayed code clears the failure counter so a legitimate
    // user's earlier mistakes don't accrue toward a later lockout.
    await Cache.delete(failKey);

    if (!secrets.mfaSessionKey)
      return c.text("MFA_SESSION_KEY not configured", 503);

    // Consume the ticket so it cannot be replayed after this success. TTL
    // covers the handoff ticket's absolute max age (verifyHandoffTicket caps
    // maxTokenAge at 10 min). POP-local best-effort like the guards above.
    await Cache.set(ticketKey, "1", { ttl: 600 });

    await setMfaCookies(c, cfg, secrets, userId, "verify");

    return c.redirect(validateRedirect(next), 303);
  });

  // --- Logout: GET {prefix}/logout ---
  // Clears edge cookies and redirects. The origin links here before (or instead
  // of) its own logout so edge cookies are always cleared as part of the
  // sign-out flow.
  app.get(`${authPrefix}/logout`, (c) => {
    const cfg = loadConfig();
    const dest = validateRedirect(c.req.query("redirect") ?? "/");
    appendCookie(c, cfg.mfaSessionCookie, "", { maxAge: 0 });
    appendCookie(c, cfg.mfaProofCookie, "", { maxAge: 0 });
    return c.redirect(dest, 302);
  });

  // --- JWKS: GET {prefix}/.well-known/jwks.json (Profile B) ---
  app.get(`${authPrefix}/.well-known/jwks.json`, (c) => {
    const publicJwk = getEnv("MFA_PROOF_PUBLIC_JWK");
    if (!publicJwk) return c.json({ error: "JWKS not configured" }, 503);
    try {
      return c.json(buildJwks(publicJwk));
    } catch {
      return c.json({ error: "Invalid MFA_PROOF_PUBLIC_JWK" }, 500);
    }
  });

  return app;
}

addEventListener("fetch", (event: FetchEvent) => {
  const cfg = loadConfig();
  const app = buildApp(cfg.authPrefix);
  event.respondWith(app.fetch(event.request));
});
