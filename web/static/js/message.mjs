/**
 * Builds the covering note the creator pastes into WhatsApp, email or chat.
 *
 * A bare key is a meaningless hundred-character string to whoever receives it:
 * they do not know where to go, that a sign-in is needed, or that it is
 * single-use. Without this the creator writes that note by hand every time.
 *
 * Kept as a pure function, separate from the page wiring, so it can be tested
 * under `node --test` without a browser.
 */

/**
 * @param {object} args
 * @param {string} args.appURL   Where this instance is reachable. Comes from the
 *   server (PUBLIC_ORIGIN + BASE_PATH) and is never hardcoded — a self-hosted
 *   or sub-path deployment must advertise its own address, not someone else's.
 * @param {string} args.shareKey
 * @param {number} args.maxViews
 * @param {string} [args.expiresAt] ISO timestamp.
 * @returns {string}
 */
export function composeShareMessage({ appURL, shareKey, maxViews, expiresAt }) {
  if (!appURL) {
    // Better to fail here than to hand someone a message with a broken link.
    throw new Error("composeShareMessage: appURL is required");
  }

  const lines = [
    `Go to ${appURL}, sign in with Google, and enter this key:`,
    "",
    // On its own line, unquoted: quotes and trailing punctuation get copied
    // along with the key and then fail to parse, and a dedicated line survives
    // the wrapping messaging apps apply to long strings.
    shareKey,
    "",
  ];

  const readable = maxViews === 1 ? "Readable once" : `Readable ${maxViews} times`;
  const expiry = formatExpiry(expiresAt);
  lines.push(expiry ? `${readable} · expires ${expiry}` : readable);
  lines.push("Once the reads run out it is deleted, and the key is the only way to open it.");

  return lines.join("\n");
}

function formatExpiry(expiresAt) {
  if (!expiresAt) return "";
  const date = new Date(expiresAt);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}
