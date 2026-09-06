/**
 * Page wiring for the signed-in app.
 *
 * Deliberately plain: no framework, no build step. The only JavaScript that
 * has to exist here is what drives crypto.mjs, because the encryption cannot
 * move to the server without giving up the property the product is for.
 */
import {
  isCryptoAvailable,
  generateKey,
  encrypt,
  decrypt,
  encodeShareKey,
  parseShareKey,
} from "./crypto.mjs";
import { composeShareMessage } from "./message.mjs";

const root = document.querySelector("main");
const BASE = root.dataset.base ?? "";
// Where this instance is reachable, from the server. Never hardcoded: a
// self-hosted or sub-path deployment must advertise its own address.
const APP_URL = root.dataset.appUrl ?? "";
const MAX_BYTES = 64 * 1024;

const $ = (id) => document.getElementById(id);
const show = (el, on = true) => { el.hidden = !on; };

async function api(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || "Something went wrong.");
  return body;
}

function fail(el, message) {
  el.textContent = message;
  show(el, true);
}

// Without a secure context there is no crypto.subtle and nothing here can
// work. Fail loudly rather than presenting an app that cannot encrypt.
if (!isCryptoAvailable()) {
  show($("secure-warning"), true);
  document.querySelectorAll("button[type=submit]").forEach((b) => (b.disabled = true));
}

// ---------- tabs ----------

const tabs = [...document.querySelectorAll(".tab")];
function select(name) {
  tabs.forEach((t) => t.setAttribute("aria-selected", String(t.dataset.tab === name)));
  document.querySelectorAll(".panel").forEach((p) => show(p, p.dataset.panel === name));
  if (name === "mine") loadMine();
}
tabs.forEach((t) => t.addEventListener("click", () => select(t.dataset.tab)));
select("share");

// ---------- share ----------

const text = $("text");
text.addEventListener("input", () => {
  const n = new TextEncoder().encode(text.value).length;
  const counter = $("counter");
  counter.textContent = `${n.toLocaleString()} / ${MAX_BYTES.toLocaleString()} bytes`;
  counter.classList.toggle("text-red-600", n > MAX_BYTES);
});

$("share-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errBox = $("share-error");
  show(errBox, false);

  const value = text.value;
  if (!value.trim()) return;
  if (new TextEncoder().encode(value).length > MAX_BYTES) {
    return fail(errBox, "Text is too large (64 KB maximum).");
  }

  const button = $("share-submit");
  button.disabled = true;
  button.textContent = "Encrypting…";
  try {
    // Key generation and encryption happen here, on this device. Only ct and
    // iv leave this function; the key goes into the share string.
    const key = generateKey();
    const { ct, iv } = await encrypt(key, value);
    const res = await api("/api/paste", {
      method: "POST",
      body: JSON.stringify({
        ct, iv,
        max_views: Number($("views").value),
        ttl_seconds: Number($("ttl").value),
      }),
    });

    const shareKey = await encodeShareKey(res.id, key);
    $("share-key").textContent = shareKey;
    $("share-message").textContent = composeShareMessage({
      appURL: APP_URL,
      shareKey,
      maxViews: res.max_views,
      expiresAt: res.expires_at,
    });
    text.value = "";
    text.dispatchEvent(new Event("input"));
    show($("share-form"), false);
    show($("share-result"), true);
  } catch (err) {
    fail(errBox, err.message);
  } finally {
    button.disabled = false;
    button.textContent = "Share";
  }
});

$("share-again").addEventListener("click", () => {
  show($("share-result"), false);
  show($("share-form"), true);
});

// ---------- reveal ----------

$("reveal-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errBox = $("reveal-error");
  show(errBox, false);

  const raw = $("key").value;
  if (!raw.trim()) return;

  const button = $("reveal-submit");
  button.disabled = true;
  button.textContent = "Decrypting…";
  try {
    // Validated locally first. A read is spent the moment the server hands
    // over the ciphertext, so a mistyped key must never reach the network.
    const { id, key } = await parseShareKey(raw);
    const { ct, iv, views_remaining: left } = await api(`/api/paste/${encodeURIComponent(id)}/reveal`, { method: "POST" });

    let plaintext;
    try {
      plaintext = await decrypt(key, ct, iv);
    } catch {
      throw new Error("The text could not be decrypted with this key.");
    }

    $("revealed").textContent = plaintext;
    const meta = $("reveal-meta");
    meta.textContent = left === 0
      ? "That was the last read — this text has now been destroyed."
      : `${left} ${left === 1 ? "read" : "reads"} remaining.`;
    meta.className = `mt-3 text-[13px] ${left === 0 ? "font-medium text-emerald-700 dark:text-emerald-400" : "text-slate-500 dark:text-slate-400"}`;
    $("key").value = "";
    show($("reveal-form"), false);
    show($("reveal-result"), true);
  } catch (err) {
    fail(errBox, err.message);
  } finally {
    button.disabled = false;
    button.textContent = "Reveal";
  }
});

$("read-again").addEventListener("click", () => {
  show($("reveal-result"), false);
  show($("reveal-form"), true);
});

// ---------- copy ----------

for (const [buttonId, sourceId, label] of [
  ["copy-message", "share-message", "Copy"],
  ["copy-key", "share-key", "Copy the key only"],
  ["copy-text", "revealed", "Copy text"],
]) {
  $(buttonId).addEventListener("click", async (e) => {
    try {
      await navigator.clipboard.writeText($(sourceId).textContent);
      e.target.textContent = "Copied";
      setTimeout(() => (e.target.textContent = label), 2000);
    } catch {
      // Clipboard access can be blocked; the text is selectable regardless.
    }
  });
}

// ---------- history ----------

async function loadMine() {
  const list = $("mine-list");
  list.textContent = "Loading…";
  try {
    const { pastes } = await api("/api/paste/mine");
    if (!pastes.length) {
      list.textContent = "You haven't shared anything yet.";
      return;
    }
    list.replaceChildren(...pastes.map(render));
  } catch (err) {
    list.textContent = err.message;
  }
}

function render(p) {
  const gone = p.ViewsRemaining === null || p.ViewsRemaining === 0;
  const li = document.createElement("div");
  li.className = "border-t border-slate-200 py-3 dark:border-slate-800";

  const head = document.createElement("div");
  head.className = "flex items-center justify-between gap-2.5";

  const id = document.createElement("code");
  id.className = "font-mono text-xs text-slate-500";
  id.textContent = `${p.ID.slice(0, 13)}…`;

  const badge = document.createElement("span");
  badge.className = `rounded-full px-2.5 py-0.5 text-xs font-medium ${
    gone ? "bg-red-50 text-red-700 dark:bg-red-950 dark:text-red-300"
         : "bg-emerald-50 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300"}`;
  badge.textContent = gone ? "Gone" : `${p.ViewsRemaining} of ${p.MaxViews} left`;

  head.append(id, badge);

  const created = document.createElement("div");
  created.className = "mt-1 text-xs text-slate-500";
  created.textContent = `Created ${new Date(p.CreatedAt).toLocaleString()}`;

  li.append(head, created);

  for (const entry of p.RevealedBy ?? []) {
    const [ts, ...rest] = entry.split(" ");
    const row = document.createElement("div");
    row.className = "mt-0.5 text-xs text-slate-500";
    row.textContent = `${rest.join(" ")} · ${new Date(ts).toLocaleString()}`;
    li.append(row);
  }
  return li;
}

// ---------- sign out ----------

$("signout").addEventListener("click", async () => {
  await fetch(`${BASE}/auth/logout`, { method: "POST", credentials: "same-origin" }).catch(() => {});
  location.href = location.pathname;
});
