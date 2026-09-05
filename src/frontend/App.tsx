import { useState } from "react";
import { useAuth } from "./contexts/AuthContext";
import { isCryptoAvailable } from "./crypto";
import { Login } from "./components/Login";
import { CreatePaste } from "./components/CreatePaste";
import { RevealPaste } from "./components/RevealPaste";
import { MyPastes } from "./components/MyPastes";
import { Avatar } from "./components/Avatar";

type Tab = "share" | "read" | "mine";

const TABS: { id: Tab; label: string }[] = [
  { id: "share", label: "Share" },
  { id: "read", label: "Read" },
  { id: "mine", label: "Your shares" },
];

export function App() {
  const { user, loading, signOut } = useAuth();
  const [tab, setTab] = useState<Tab>("share");

  // Without a secure context there is no crypto.subtle and nothing here can
  // work. Fail loudly rather than shipping an app that silently cannot encrypt.
  if (!isCryptoAvailable()) {
    return (
      <main className="shell">
        <div className="card centered">
          <h1 className="brand">ShareText</h1>
          <div className="alert error">
            Browser encryption is unavailable. ShareText requires a secure connection — open it over
            HTTPS or on localhost.
          </div>
        </div>
      </main>
    );
  }

  if (loading) {
    return (
      <main className="shell">
        <div className="card centered">
          <p className="note">Loading…</p>
        </div>
      </main>
    );
  }

  if (!user) {
    return (
      <main className="shell">
        <Login />
      </main>
    );
  }

  return (
    <main className="shell">
      <header className="topbar">
        <span className="brand small">ShareText</span>
        <div className="who">
          <Avatar user={user} />
          <span className="email">{user.email}</span>
          <button className="btn link" onClick={signOut}>
            Sign out
          </button>
        </div>
      </header>

      <nav className="tabs" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            className={`tab ${tab === t.id ? "active" : ""}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </nav>

      {tab === "share" && <CreatePaste />}
      {tab === "read" && <RevealPaste />}
      {tab === "mine" && <MyPastes />}

      <footer className="foot">
        Encrypted in your browser with AES-256-GCM. The server stores ciphertext only.
      </footer>
    </main>
  );
}
