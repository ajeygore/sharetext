import { useState } from "react";

interface Props {
  shareKey: string;
  maxViews: number;
  expiresAt: string;
  onDone: () => void;
}

export function ShareKeyDisplay({ shareKey, maxViews, expiresAt, onDone }: Props) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(shareKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard can be blocked by permissions; the key is selectable anyway.
    }
  }

  return (
    <div className="card">
      <h2>Your key is ready</h2>
      <div className="alert warn">
        This key is shown <strong>once</strong>. Part of it never reaches our server, so if you lose
        it the text cannot be recovered by anyone — including us.
      </div>

      <label className="label">Share key</label>
      <code className="sharekey" onClick={(e) => window.getSelection()?.selectAllChildren(e.currentTarget)}>
        {shareKey}
      </code>

      <div className="row">
        <button className="btn primary" onClick={copy}>
          {copied ? "Copied" : "Copy key"}
        </button>
        <button className="btn" onClick={onDone}>
          Share another
        </button>
      </div>

      <p className="note">
        Readable {maxViews} {maxViews === 1 ? "time" : "times"} · expires{" "}
        {new Date(expiresAt).toLocaleString()}
      </p>
      <p className="note">
        Send it through a channel you trust. Anyone with this key and a Google account can read the
        text.
      </p>
    </div>
  );
}
