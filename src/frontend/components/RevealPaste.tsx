import { useState } from "react";
import { revealPaste } from "../api";
import { decrypt, parseShareKey, ShareKeyError } from "../crypto";

export function RevealPaste() {
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ text: string; viewsRemaining: number } | null>(null);
  const [copied, setCopied] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!input.trim() || busy) return;

    setBusy(true);
    setError(null);
    try {
      // Validated locally first. A view is spent the moment the server hands
      // over the ciphertext, so a mistyped key must never reach the network.
      const { id, key } = await parseShareKey(input);
      const { ct, iv, viewsRemaining } = await revealPaste(id);

      let text: string;
      try {
        text = await decrypt(key, ct, iv);
      } catch {
        throw new Error("The text could not be decrypted with this key.");
      }

      setResult({ text, viewsRemaining });
      setInput("");
    } catch (err) {
      setError(
        err instanceof ShareKeyError || err instanceof Error
          ? err.message
          : "Could not read the text."
      );
    } finally {
      setBusy(false);
    }
  }

  async function copy() {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(result.text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* selectable regardless */
    }
  }

  if (result) {
    return (
      <div className="card">
        <h2>Revealed</h2>
        <pre className="revealed">{result.text}</pre>
        <div className="row">
          <button className="btn primary" onClick={copy}>
            {copied ? "Copied" : "Copy text"}
          </button>
          <button
            className="btn"
            onClick={() => {
              setResult(null);
              setCopied(false);
            }}
          >
            Read another
          </button>
        </div>
        <p className={`note ${result.viewsRemaining === 0 ? "strong" : ""}`}>
          {result.viewsRemaining === 0
            ? "That was the last read — this text has now been destroyed."
            : `${result.viewsRemaining} ${result.viewsRemaining === 1 ? "read" : "reads"} remaining.`}
        </p>
      </div>
    );
  }

  return (
    <form className="card" onSubmit={submit}>
      <h2>Read shared text</h2>
      <label className="label" htmlFor="key">
        Share key
      </label>
      <textarea
        id="key"
        rows={3}
        className="mono"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="Paste the key you were given…"
        spellCheck={false}
        autoComplete="off"
      />

      {error && <div className="alert error">{error}</div>}

      <button className="btn primary block" type="submit" disabled={busy || !input.trim()}>
        {busy ? "Decrypting…" : "Reveal"}
      </button>
      <p className="note">Reading uses up one of the text's remaining reads.</p>
    </form>
  );
}
