import assert from "node:assert/strict";
import test from "node:test";

import { revokeSession } from "../src/lib/auth-session.ts";

test("sign-out sends the token only in the authorization header and waits for confirmed revocation", async () => {
  let release;
  let requestSeen = false;
  let finished = false;
  const response = new Promise((resolve) => {
    release = resolve;
  });
  const pending = revokeSession("test-session", (url, init) => {
    requestSeen = true;
    assert.equal(url, "/api/auth/logout");
    assert.equal(init.method, "POST");
    assert.equal(init.credentials, "same-origin");
    assert.equal(new Headers(init.headers).get("Authorization"), "Bearer test-session");
    assert.ok(init.signal instanceof AbortSignal);
    assert.equal(init.signal.aborted, false);
    return response;
  }).then(() => {
    finished = true;
  });

  await Promise.resolve();
  assert.equal(requestSeen, true);
  assert.equal(finished, false);
  release(Response.json({ ok: true }));
  await pending;
  assert.equal(finished, true);
});

test("an expired or already revoked session is safe to discard", async () => {
  await revokeSession("expired-session", async () => new Response(null, { status: 401 }));
});

test("cookie-only sessions still reach the server without an empty bearer header", async () => {
  await revokeSession(null, async (url, init) => {
    assert.equal(url, "/api/auth/logout");
    assert.equal(init.credentials, "same-origin");
    assert.equal(new Headers(init.headers).has("Authorization"), false);
    return Response.json({ ok: true });
  });
});

for (const status of [202, 204, 403, 500, 503]) {
  test(`HTTP ${status} does not confirm server-side revocation`, async () => {
    await assert.rejects(
      revokeSession("test-session", async () => new Response(null, { status })),
      /did not confirm sign-out/,
    );
  });
}

for (const body of [{ ok: false }, {}, { ok: "true" }, null]) {
  test(`HTTP 200 with ${JSON.stringify(body)} does not confirm server-side revocation`, async () => {
    await assert.rejects(
      revokeSession("test-session", async () => Response.json(body)),
      /did not confirm sign-out/,
    );
  });
}

test("a successful HTML fallback is not mistaken for the logout endpoint", async () => {
  await assert.rejects(
    revokeSession("test-session", async () => new Response("<html>Sign in</html>")),
    SyntaxError,
  );
});

test("network failures and timeouts remain retryable rather than confirming revocation", async () => {
  for (const cause of [new TypeError("Network unavailable"), new DOMException("Request timed out", "TimeoutError")]) {
    await assert.rejects(
      revokeSession("test-session", async () => {
        throw cause;
      }),
      (error) => error === cause,
    );
  }
});
