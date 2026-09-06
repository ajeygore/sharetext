// The share message is a pure function so it can be verified without a
// browser: what the creator pastes into WhatsApp or email is the product's
// last mile, and it should not need a manual click-through to check.
import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { composeShareMessage } from "../web/static/js/message.mjs";

const KEY = "3f2504e0-4f89-41d3-9a0c-0305e82c3301.aGVsbG8td29ybGQtc2VjcmV0LWtleS1oZXJlLTMyYnl0ZXM.fX8";
const EXPIRES = "2026-09-06T19:30:00Z";

const compose = (over = {}) =>
  composeShareMessage({
    appURL: "https://share.tnkrhaus.dev",
    shareKey: KEY,
    maxViews: 2,
    expiresAt: EXPIRES,
    ...over,
  });

describe("composeShareMessage", () => {
  test("tells the recipient where to go, to sign in, and gives the key", () => {
    const msg = compose();
    assert.match(msg, /https:\/\/share\.tnkrhaus\.dev/);
    assert.match(msg, /sign in with Google/i);
    assert.ok(msg.includes(KEY), "message does not contain the key");
  });

  // Quotes and trailing punctuation get copied along with the key and then
  // fail to parse. A line of its own also survives the wrapping that
  // messaging apps apply to long strings.
  test("puts the key alone on its own line, unquoted and unpunctuated", () => {
    const line = compose()
      .split("\n")
      .find((l) => l.includes(KEY));
    assert.equal(line, KEY, `key line was ${JSON.stringify(line)}`);
  });

  test("a naive round-trip of that line recovers the key exactly", () => {
    const line = compose()
      .split("\n")
      .find((l) => l.includes(KEY));
    assert.equal(line.trim(), KEY);
  });

  test("states the remaining reads and the expiry", () => {
    const msg = compose({ maxViews: 3 });
    assert.match(msg, /3 times/);
    assert.match(msg, /expires/i);
  });

  test("says 'once' rather than '1 times' for a single read", () => {
    const msg = compose({ maxViews: 1 });
    assert.match(msg, /once/i);
    assert.doesNotMatch(msg, /1 times/);
  });

  // A self-hosted instance, or one mounted under a path, must advertise its
  // own address — otherwise it sends people to somebody else's server.
  test("uses whatever origin it is given, including a sub-path", () => {
    assert.match(
      compose({ appURL: "https://example.com/sharetext" }),
      /https:\/\/example\.com\/sharetext/
    );
    assert.doesNotMatch(compose({ appURL: "http://localhost:3000" }), /tnkrhaus/);
  });

  test("refuses to compose without an origin rather than emitting a broken link", () => {
    assert.throws(() => compose({ appURL: "" }));
  });

  test("omits the expiry line gracefully when there is no date", () => {
    const msg = compose({ expiresAt: "" });
    assert.ok(msg.includes(KEY));
    assert.doesNotMatch(msg, /Invalid Date/);
  });
});
