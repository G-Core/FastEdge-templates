import { test } from "node:test";
import assert from "node:assert/strict";
import { validateRedirect } from "@sso/core/util/redirect";

const ALLOWED = ["https://mysite.com", "https://other.example.com"];

test("validateRedirect: undefined → /", () => {
  assert.equal(validateRedirect(undefined, ALLOWED), "/");
});

test("validateRedirect: empty string → /", () => {
  assert.equal(validateRedirect("", ALLOWED), "/");
});

test("validateRedirect: relative path allowed", () => {
  assert.equal(validateRedirect("/dashboard", ALLOWED), "/dashboard");
});

test("validateRedirect: relative path with query allowed", () => {
  assert.equal(validateRedirect("/page?foo=bar", ALLOWED), "/page?foo=bar");
});

test("validateRedirect: protocol-relative URL rejected", () => {
  assert.equal(validateRedirect("//evil.com/steal", ALLOWED), "/");
});

test("validateRedirect: backslash protocol-relative bypass rejected", () => {
  assert.equal(validateRedirect("/\\evil.com", ALLOWED), "/");
});

test("validateRedirect: slash-backslash bypass rejected", () => {
  assert.equal(validateRedirect("/\\/evil.com", ALLOWED), "/");
});

test("validateRedirect: forward-slash-backslash bypass rejected", () => {
  assert.equal(validateRedirect("/\\\\evil.com", ALLOWED), "/");
});

test("validateRedirect: CRLF in relative path rejected (response-splitting)", () => {
  assert.equal(validateRedirect("/path\r\nSet-Cookie: x=y", ALLOWED), "/");
});

test("validateRedirect: bare LF in relative path rejected", () => {
  assert.equal(validateRedirect("/path\nLocation: https://evil.com", ALLOWED), "/");
});

test("validateRedirect: NUL byte in relative path rejected", () => {
  assert.equal(validateRedirect("/path\u0000evil", ALLOWED), "/");
});

test("validateRedirect: allowed absolute URL passes through", () => {
  assert.equal(
    validateRedirect("https://mysite.com/path", ALLOWED),
    "https://mysite.com/path",
  );
});

test("validateRedirect: allowed absolute URL with query passes through", () => {
  assert.equal(
    validateRedirect("https://other.example.com/callback?ref=1", ALLOWED),
    "https://other.example.com/callback?ref=1",
  );
});

test("validateRedirect: off-origin absolute URL rejected", () => {
  assert.equal(validateRedirect("https://evil.com/steal", ALLOWED), "/");
});

test("validateRedirect: javascript: URL rejected", () => {
  assert.equal(validateRedirect("javascript:alert(1)", ALLOWED), "/");
});

test("validateRedirect: data: URL rejected", () => {
  assert.equal(validateRedirect("data:text/html,<script>", ALLOWED), "/");
});

test("validateRedirect: empty allowlist rejects absolute URLs", () => {
  assert.equal(validateRedirect("https://mysite.com/path", []), "/");
});

test("validateRedirect: empty allowlist still allows relative URLs", () => {
  assert.equal(validateRedirect("/protected", []), "/protected");
});
