import { useEffect, useState } from "react";
import { devLogin, fetchAuthConfig, loginUrl } from "../api";

const ERRORS: Record<string, string> = {
  state_mismatch: "That sign-in attempt could not be verified. Please try again.",
  token_exchange_failed: "Google could not complete the sign-in. Please try again.",
  profile_fetch_failed: "Could not read your Google profile. Please try again.",
  unverified_email: "Your Google email address is not verified.",
  authorization_failed: "Sign-in was cancelled.",
  access_denied: "Sign-in was cancelled.",
  oauth_failed: "Sign-in failed. Please try again.",
};

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
    <div className="card centered">
      <h1 className="brand">ShareText</h1>
      <p className="lede">
        Share a piece of text that can only be read a set number of times, then destroys itself.
      </p>
      <p className="note">
        Text is encrypted in your browser. The server only ever stores bytes it cannot read.
      </p>

      {error && <div className="alert error">{ERRORS[error] ?? "Sign-in failed."}</div>}

      {config && !config.googleConfigured && (
        <div className="alert warn">
          Google sign-in is not configured on this server.
        </div>
      )}

      <a className="btn primary block" href={loginUrl()}>
        Sign in with Google
      </a>

      {config?.devLogin && (
        <div className="devbox">
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
