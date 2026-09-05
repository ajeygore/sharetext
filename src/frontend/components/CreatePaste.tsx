import { useState } from "react";
import { createPaste } from "../api";
import { encodeShareKey, encrypt, generateKey } from "../crypto";
import { MAX_PLAINTEXT_BYTES, MAX_VIEWS_LIMIT, TTL_OPTIONS } from "../../shared/types";
import { ShareKeyDisplay } from "./ShareKeyDisplay";

interface Created {
  shareKey: string;
  maxViews: number;
  expiresAt: string;
}

export function CreatePaste() {
  const [text, setText] = useState("");
  const [maxViews, setMaxViews] = useState(1);
  const [ttlSeconds, setTtlSeconds] = useState<number>(TTL_OPTIONS[1].seconds);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<Created | null>(null);

  const byteLength = new TextEncoder().encode(text).length;
  const tooLarge = byteLength > MAX_PLAINTEXT_BYTES;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!text.trim() || tooLarge || busy) return;

    setBusy(true);
    setError(null);
    try {
      // Key generation and encryption happen here, in the browser. Only `ct`
      // and `iv` leave this function; the key goes into the share string.
      const key = generateKey();
      const { ct, iv } = await encrypt(key, text);
      const res = await createPaste({ ct, iv, maxViews, ttlSeconds });

      setCreated({
        shareKey: await encodeShareKey(res.id, key),
        maxViews: res.maxViews,
        expiresAt: res.expiresAt,
      });
      setText("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not share the text.");
    } finally {
      setBusy(false);
    }
  }

  if (created) {
    return <ShareKeyDisplay {...created} onDone={() => setCreated(null)} />;
  }

  return (
    <form className="card" onSubmit={submit}>
      <h2>Share text</h2>

      <label className="label" htmlFor="text">
        Text to share
      </label>
      <textarea
        id="text"
        rows={9}
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder="Paste the text you want to share…"
        spellCheck={false}
        autoComplete="off"
      />
      <div className={`counter ${tooLarge ? "over" : ""}`}>
        {byteLength.toLocaleString()} / {MAX_PLAINTEXT_BYTES.toLocaleString()} bytes
      </div>

      <div className="grid2">
        <div>
          <label className="label" htmlFor="views">
            Times it can be read
          </label>
          <select
            id="views"
            value={maxViews}
            onChange={(e) => setMaxViews(Number(e.target.value))}
          >
            {Array.from({ length: MAX_VIEWS_LIMIT }, (_, i) => i + 1).map((n) => (
              <option key={n} value={n}>
                {n} {n === 1 ? "time" : "times"}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="label" htmlFor="ttl">
            Expires after
          </label>
          <select
            id="ttl"
            value={ttlSeconds}
            onChange={(e) => setTtlSeconds(Number(e.target.value))}
          >
            {TTL_OPTIONS.map((t) => (
              <option key={t.seconds} value={t.seconds}>
                {t.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && <div className="alert error">{error}</div>}

      <button className="btn primary block" type="submit" disabled={busy || !text.trim() || tooLarge}>
        {busy ? "Encrypting…" : "Share"}
      </button>
      <p className="note">
        Encrypted on this device with AES-256-GCM. The key is never sent to the server.
      </p>
    </form>
  );
}
