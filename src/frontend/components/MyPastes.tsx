import { useEffect, useState } from "react";
import { fetchMyPastes } from "../api";
import type { PasteSummary } from "../../shared/types";

function status(p: PasteSummary): { label: string; tone: string } {
  if (p.viewsRemaining === null) return { label: "Gone", tone: "gone" };
  if (p.viewsRemaining === 0) return { label: "Gone", tone: "gone" };
  return { label: `${p.viewsRemaining} of ${p.maxViews} left`, tone: "live" };
}

export function MyPastes() {
  const [pastes, setPastes] = useState<PasteSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchMyPastes()
      .then((r) => setPastes(r.pastes))
      .catch((e) => setError(e instanceof Error ? e.message : "Could not load history."));
  }, []);

  if (error) return <div className="card"><div className="alert error">{error}</div></div>;
  if (!pastes) return <div className="card"><p className="note">Loading…</p></div>;

  return (
    <div className="card">
      <h2>Your shares</h2>
      <p className="note">
        Only who read each item and how many reads are left. The text itself is not recoverable from
        here — we never had the key.
      </p>

      {pastes.length === 0 ? (
        <p className="empty">You haven't shared anything yet.</p>
      ) : (
        <ul className="list">
          {pastes.map((p) => {
            const s = status(p);
            return (
              <li key={p.id}>
                <div className="listhead">
                  <code className="id">{p.id.slice(0, 10)}…</code>
                  <span className={`badge ${s.tone}`}>{s.label}</span>
                </div>
                <div className="note">Created {new Date(p.createdAt).toLocaleString()}</div>
                {p.revealedBy.length > 0 && (
                  <ul className="readers">
                    {p.revealedBy.map((entry, i) => {
                      const [ts, ...rest] = entry.split(" ");
                      return (
                        <li key={i}>
                          {rest.join(" ")} · {new Date(ts).toLocaleString()}
                        </li>
                      );
                    })}
                  </ul>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
