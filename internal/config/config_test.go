package config

import "testing"

func TestSecureCookiesFollowTheOrigin(t *testing.T) {
	// Setting Secure on plain-HTTP localhost makes the browser drop the cookie
	// and the login loop never closes; omitting it on HTTPS leaks the session.
	for origin, want := range map[string]bool{
		"https://share.tnkrhaus.dev": true,
		"http://localhost:3000":      false,
		"http://127.0.0.1:8080":      false,
	} {
		if got := (Config{PublicOrigin: origin}).SecureCookies(); got != want {
			t.Errorf("%s: SecureCookies() = %v, want %v", origin, got, want)
		}
	}
}

func TestRedirectURI(t *testing.T) {
	for _, tc := range []struct{ origin, base, want string }{
		{"https://share.tnkrhaus.dev", "", "https://share.tnkrhaus.dev/auth/google/callback"},
		{"https://example.com", "/sharetext", "https://example.com/sharetext/auth/google/callback"},
		{"https://example.com/", "/sharetext/", "https://example.com/sharetext/auth/google/callback"},
	} {
		c := Config{PublicOrigin: tc.origin, BasePath: tc.base}.normalise()
		if got := c.RedirectURI(); got != tc.want {
			t.Errorf("origin=%q base=%q -> %q, want %q", tc.origin, tc.base, got, tc.want)
		}
	}
}

func TestProductionDemandsASessionSecret(t *testing.T) {
	if err := (Config{Production: true, SessionSecret: ""}).Validate(); err == nil {
		t.Fatal("production accepted an empty session secret")
	}
	if err := (Config{Production: true, SessionSecret: "short"}).Validate(); err == nil {
		t.Fatal("production accepted a trivially short session secret")
	}
	if err := (Config{Production: true, SessionSecret: "0123456789abcdef0123456789abcdef"}).Validate(); err != nil {
		t.Fatalf("valid production config rejected: %v", err)
	}
}

func TestGoogleConfigured(t *testing.T) {
	if (Config{}).GoogleConfigured() {
		t.Error("empty credentials reported as configured")
	}
	if (Config{GoogleClientID: "x"}).GoogleConfigured() {
		t.Error("half-configured credentials reported as configured")
	}
	if !(Config{GoogleClientID: "x", GoogleClientSecret: "y"}).GoogleConfigured() {
		t.Error("complete credentials reported as unconfigured")
	}
}

func TestAppURL(t *testing.T) {
	// The share message advertises this address. A self-hosted or sub-path
	// instance must produce its own, or it sends people to another server.
	for _, tc := range []struct{ origin, base, want string }{
		{"https://share.tnkrhaus.dev", "", "https://share.tnkrhaus.dev"},
		{"https://share.tnkrhaus.dev/", "", "https://share.tnkrhaus.dev"},
		{"https://example.com", "/sharetext", "https://example.com/sharetext"},
		{"https://example.com/", "/sharetext/", "https://example.com/sharetext"},
		{"http://localhost:3000", "", "http://localhost:3000"},
	} {
		c := Config{PublicOrigin: tc.origin, BasePath: tc.base}.normalise()
		if got := c.AppURL(); got != tc.want {
			t.Errorf("origin=%q base=%q -> %q, want %q", tc.origin, tc.base, got, tc.want)
		}
	}
}
