import { useEffect, useState } from "react";
import { devLogin, fetchAuthConfig, loginUrl } from "../api";
import { GoogleButton } from "./GoogleButton";

const ERRORS: Record<string, string> = {
  state_mismatch: "That sign-in attempt could not be verified. Please try again.",
  token_exchange_failed: "Google could not complete the sign-in. Please try again.",
  profile_fetch_failed: "Could not read your Google profile. Please try again.",
  unverified_email: "Your Google email address is not verified, so we can't sign you in.",
  authorization_failed: "Sign-in was cancelled.",
  access_denied: "Sign-in was cancelled.",
  oauth_failed: "Sign-in failed. Please try again.",
};

const FEATURES = [
  {
    title: "Encrypted before it leaves your device",
    body: "Your text is encrypted in this browser with AES-256-GCM. The server only ever receives bytes it has no key for.",
    icon: (
      <path d="M12 2 4 5.5v5.2c0 4.6 3.2 8.9 8 10.3 4.8-1.4 8-5.7 8-10.3V5.5L12 2Z" />
    ),
  },
  {
    title: "Reads are counted, then it's gone",
    body: "Choose how many times it can be opened. On the last read the record is deleted outright — not flagged, deleted.",
    icon: <path d="M12 7v5l3.5 2M21 12a9 9 0 1 1-9-9 9 9 0 0 1 9 9Z" />,
  },
  {
    title: "Nothing left to clean up",
    body: "Everything carries an expiry. Whatever isn't read in time removes itself without anyone having to remember.",
    icon: <path d="M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13M10 11v6M14 11v6" />,
  },
];

export function Login() {
  const [config, setConfig] = useState<{ googleConfigured: boolean; devLogin: boolean } | null>(
    null
  );
  const [devEmail, setDevEmail] = useState("dev@localhost");
  const error = new URLSearchParams(window.location.search).get("error");

  useEffect(() => {
    fetchAuthConfig()
      .then(setConfig)
      .catch(() => setConfig({ googleConfigured: true, devLogin: false }));
  }, []);

  async function signInAsDev() {
    await devLogin(devEmail);
    window.location.href = window.location.pathname;
  }

  return (
    <div className="landing">
      <header className="landing-head">
        <div className="mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <rect x="4" y="10" width="16" height="11" rx="2" />
            <path d="M8 10V7a4 4 0 0 1 8 0v3" />
          </svg>
        </div>
        <h1>ShareText</h1>
        <p className="landing-lede">
          Share a piece of text that can only be read a set number of times, then destroys itself.
        </p>
      </header>

      <div className="card signin-card">
        {error && <div className="alert error">{ERRORS[error] ?? "Sign-in failed."}</div>}

        {config && !config.googleConfigured && (
          <div className="alert warn">
            Google sign-in is not configured on this server, so nobody can sign in yet.
          </div>
        )}

        <GoogleButton href={loginUrl()} />

        <p className="signin-why">
          Sign-in is required to create a share and to open one, so every read is attributable.
        </p>

        <details className="disclosure">
          <summary>What Google shares with us</summary>
          <div className="disclosure-body">
            <ul className="ticks">
              <li>
                <strong>Your name, email address and profile picture.</strong> Your email
                identifies your shares and is recorded against any share you open.
              </li>
              <li>
                <strong>Nothing else.</strong> We ask only for your basic profile — no access to
                Gmail, Drive, Contacts or Calendar.
              </li>
              <li>
                <strong>We never post or send anything</strong> on your behalf.
              </li>
            </ul>
            <p className="disclosure-note">
              We store no password. You can revoke access at any time from your{" "}
              <span className="nowrap">Google Account → Security → Third-party access</span>.
            </p>
          </div>
        </details>
      </div>

      <ul className="features">
        {FEATURES.map((f) => (
          <li key={f.title}>
            <span className="feature-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
                {f.icon}
              </svg>
            </span>
            <div>
              <h2>{f.title}</h2>
              <p>{f.body}</p>
            </div>
          </li>
        ))}
      </ul>

      <section className="built">
        <h2 className="built-title">Open source, and built to know nothing</h2>
        <p className="built-lede">
          ShareText is open source — audit the encryption, run your own, or open an issue. The key
          is generated and used entirely in your browser, so there is no server-side path to your
          plaintext to trust.{" "}
          <a
            className="built-link"
            href="https://github.com/ajeygore/sharetext"
            target="_blank"
            rel="noreferrer"
          >
            github.com/ajeygore/sharetext&nbsp;↗
          </a>
        </p>
        <ul className="stack">
          <li>React + TypeScript</li>
          <li>Web Crypto · AES-256-GCM</li>
          <li>Bun</li>
          <li>Redis</li>
          <li>Google OAuth</li>
          <li>Caddy · Let's Encrypt</li>
        </ul>
      </section>

      <p className="landing-foot">
        The encryption key never reaches the server — it travels only in the key you copy out. If
        you lose it, the text cannot be recovered by anyone, us included.
      </p>

      {config?.devLogin && (
        <div className="card devbox">
          <label className="label" htmlFor="devEmail">
            Development sign-in
          </label>
          <div className="row">
            <input
              id="devEmail"
              value={devEmail}
              onChange={(e) => setDevEmail(e.target.value)}
              autoComplete="off"
            />
            <button className="btn" onClick={signInAsDev}>
              Continue
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
