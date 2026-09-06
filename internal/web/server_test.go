package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ajeygore/sharetext/internal/config"
	"github.com/ajeygore/sharetext/internal/session"
	"github.com/ajeygore/sharetext/internal/store"
	"github.com/ajeygore/sharetext/web"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func redisAddr() string {
	if a := os.Getenv("REDIS_ADDR"); a != "" {
		return a
	}
	return "127.0.0.1:6380"
}

func newServer(t *testing.T, basePath string) (*Server, *store.Store) {
	t.Helper()
	st, err := store.New(store.Options{Addr: redisAddr()})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Ping(context.Background()); err != nil {
		t.Skipf("Redis not reachable (run `docker compose up -d`): %v", err)
	}
	_ = st.FlushForTests(context.Background())
	t.Cleanup(func() { _ = st.FlushForTests(context.Background()); _ = st.Close() })

	cfg := config.Config{
		Port: 3000, BasePath: basePath, PublicOrigin: "http://localhost:3000",
		SessionSecret: testSecret, GoogleClientID: "id", GoogleClientSecret: "secret",
		RedisAddr: redisAddr(),
	}
	srv, err := New(cfg, st)
	if err != nil {
		t.Fatal(err)
	}
	return srv, st
}

func signedIn(t *testing.T, email string) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := session.New(testSecret, "/", false).Set(rec, session.User{Email: email, Name: email}); err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()[0]
}

func do(srv *Server, method, path string, body string, c *http.Cookie) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if c != nil {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, r)
	return rec
}

const validBody = `{"ct":"Y2lwaGVydGV4dA","iv":"aXZpdml2aXZpdg","max_views":1,"ttl_seconds":3600}`

func TestHealth(t *testing.T) {
	srv, _ := newServer(t, "")
	rec := do(srv, http.MethodGet, "/up", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["redis"] != true {
		t.Errorf("redis = %v, want true", body["redis"])
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv, _ := newServer(t, "")
	h := do(srv, http.MethodGet, "/", "", nil).Header()

	csp := h.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "frame-ancestors 'none'", "object-src 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP missing %q: %s", want, csp)
		}
	}
	// Google rotates avatars across lh3-lh6, so pinning one host breaks
	// pictures for some accounts and not others.
	if !strings.Contains(csp, "googleusercontent.com") {
		t.Errorf("CSP does not allow Google avatars: %s", csp)
	}
	// Decrypted text must never ride along in a Referer to anywhere.
	if h.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", h.Get("Referrer-Policy"))
	}
	if h.Get("X-Frame-Options") != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", h.Get("X-Frame-Options"))
	}
}

func TestAuthenticationRequired(t *testing.T) {
	srv, _ := newServer(t, "")
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/paste", validBody},
		{http.MethodPost, "/api/paste/3f2504e0-4f89-41d3-9a0c-0305e82c3301/reveal", ""},
		{http.MethodGet, "/api/paste/mine", ""},
	} {
		if rec := do(srv, tc.method, tc.path, tc.body, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
}

func TestTamperedSessionRejected(t *testing.T) {
	srv, _ := newServer(t, "")
	c := signedIn(t, "a@example.com")
	c.Value = c.Value[:len(c.Value)-3] + "xyz"
	if rec := do(srv, http.MethodPost, "/api/paste", validBody, c); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
}

func TestCreateValidation(t *testing.T) {
	srv, _ := newServer(t, "")
	c := signedIn(t, "a@example.com")

	cases := map[string]struct {
		body string
		want int
	}{
		"non-base64url ciphertext": {`{"ct":"not base64!!","iv":"aXY","max_views":1,"ttl_seconds":3600}`, 400},
		"empty ciphertext":         {`{"ct":"","iv":"aXY","max_views":1,"ttl_seconds":3600}`, 400},
		"overlong iv":              {`{"ct":"Y3Q","iv":"` + strings.Repeat("a", 64) + `","max_views":1,"ttl_seconds":3600}`, 400},
		"zero views":               {`{"ct":"Y3Q","iv":"aXY","max_views":0,"ttl_seconds":3600}`, 400},
		"excessive views":          {`{"ct":"Y3Q","iv":"aXY","max_views":999,"ttl_seconds":3600}`, 400},
		"arbitrary ttl":            {`{"ct":"Y3Q","iv":"aXY","max_views":1,"ttl_seconds":12345}`, 400},
		"malformed json":           {`{not json`, 400},
		"oversized ciphertext":     {`{"ct":"` + strings.Repeat("A", maxCiphertextChars+1) + `","iv":"aXY","max_views":1,"ttl_seconds":3600}`, 413},
	}
	for name, tc := range cases {
		if rec := do(srv, http.MethodPost, "/api/paste", tc.body, c); rec.Code != tc.want {
			t.Errorf("%s: status %d, want %d", name, rec.Code, tc.want)
		}
	}
}

func TestCreateReturnsUUID(t *testing.T) {
	srv, _ := newServer(t, "")
	rec := do(srv, http.MethodPost, "/api/paste", validBody, signedIn(t, "a@example.com"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var got struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if len(got.ID) != 36 || strings.Count(got.ID, "-") != 4 || got.ID[14] != '4' {
		t.Fatalf("id %q is not a UUIDv4", got.ID)
	}
}

func TestRevealFlow(t *testing.T) {
	srv, _ := newServer(t, "")
	creator := signedIn(t, "creator@example.com")

	rec := do(srv, http.MethodPost, "/api/paste",
		`{"ct":"Y2lwaGVydGV4dA","iv":"aXZpdml2aXZpdg","max_views":2,"ttl_seconds":3600}`, creator)
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	reader := signedIn(t, "reader@example.com")
	first := do(srv, http.MethodPost, "/api/paste/"+created.ID+"/reveal", "", reader)
	if first.Code != http.StatusOK {
		t.Fatalf("first reveal %d: %s", first.Code, first.Body)
	}
	var got struct {
		CT             string `json:"ct"`
		ViewsRemaining int    `json:"views_remaining"`
	}
	_ = json.Unmarshal(first.Body.Bytes(), &got)
	if got.CT != "Y2lwaGVydGV4dA" || got.ViewsRemaining != 1 {
		t.Fatalf("got %+v", got)
	}

	if rec := do(srv, http.MethodPost, "/api/paste/"+created.ID+"/reveal", "", reader); rec.Code != http.StatusOK {
		t.Fatalf("second reveal %d", rec.Code)
	}
	if rec := do(srv, http.MethodPost, "/api/paste/"+created.ID+"/reveal", "", reader); rec.Code != http.StatusNotFound {
		t.Fatalf("third reveal %d, want 404", rec.Code)
	}

	hist := do(srv, http.MethodGet, "/api/paste/mine", "", creator)
	if !strings.Contains(hist.Body.String(), "reader@example.com") {
		t.Errorf("history lost the audit trail: %s", hist.Body)
	}
}

// A prober must not be able to tell "this id was real and is used up" from
// "this id never existed" — that would confirm a paste's existence and leak
// the timing of other people's reads.
func TestNotFoundResponsesAreIndistinguishable(t *testing.T) {
	srv, _ := newServer(t, "")
	c := signedIn(t, "a@example.com")

	rec := do(srv, http.MethodPost, "/api/paste", validBody, c)
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	do(srv, http.MethodPost, "/api/paste/"+created.ID+"/reveal", "", c) // exhaust it

	// Ids that actually reach the handler: consumed, never-existed, a valid
	// UUID of the wrong version, and something that is not a UUID at all.
	bodies := map[string]bool{}
	for _, id := range []string{
		created.ID,
		"6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		"00000000-0000-0000-0000-000000000000",
		"not-a-uuid",
	} {
		r := do(srv, http.MethodPost, "/api/paste/"+id+"/reveal", "", c)
		if r.Code != http.StatusNotFound {
			t.Fatalf("id %q -> %d, want 404", id, r.Code)
		}
		bodies[r.Body.String()] = true
	}
	if len(bodies) != 1 {
		t.Fatalf("404 bodies differ between cases: %v", bodies)
	}
}

// Traversal in the id segment is normalised by net/http's mux before routing,
// so it never reaches the handler. Assert what actually matters: it cannot
// reach anything, rather than that it produces a particular status.
func TestPathTraversalReachesNothing(t *testing.T) {
	srv, _ := newServer(t, "")
	c := signedIn(t, "a@example.com")

	for _, id := range []string{"../../etc/passwd", "..%2f..%2fetc%2fpasswd", "....//....//etc/passwd"} {
		rec := do(srv, http.MethodPost, "/api/paste/"+id+"/reveal", "", c)
		if rec.Code == http.StatusOK {
			t.Errorf("traversal %q returned 200: %s", id, rec.Body)
		}
		if strings.Contains(rec.Body.String(), "root:") {
			t.Errorf("traversal %q leaked file content", id)
		}
	}
}

func TestHistoryIsScopedToTheUser(t *testing.T) {
	srv, _ := newServer(t, "")
	do(srv, http.MethodPost, "/api/paste", validBody, signedIn(t, "owner@example.com"))

	rec := do(srv, http.MethodGet, "/api/paste/mine", "", signedIn(t, "stranger@example.com"))
	if strings.Contains(rec.Body.String(), `"id"`) {
		t.Fatalf("one user's pastes leaked to another: %s", rec.Body)
	}
}

func TestRateLimit(t *testing.T) {
	srv, _ := newServer(t, "")
	c := signedIn(t, "spammer@example.com")
	saw429 := false
	for i := 0; i < revealRateLimit+10; i++ {
		if do(srv, http.MethodPost, "/api/paste/6ba7b810-9dad-11d1-80b4-00c04fd430c8/reveal", "", c).Code == http.StatusTooManyRequests {
			saw429 = true
			break
		}
	}
	if !saw429 {
		t.Fatal("reveal attempts were never rate limited")
	}
}

// The same binary has to serve a domain root and a sub-path, so both are
// asserted here rather than the sub-path case being met first in production.
func TestMountedUnderSubPath(t *testing.T) {
	srv, _ := newServer(t, "/sharetext")
	if rec := do(srv, http.MethodGet, "/sharetext/up", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("/sharetext/up = %d", rec.Code)
	}
	rec := do(srv, http.MethodGet, "/", "", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/sharetext/" {
		t.Fatalf("root = %d -> %q, want 302 -> /sharetext/", rec.Code, rec.Header().Get("Location"))
	}
	if rec := do(srv, http.MethodGet, "/api/paste/mine", "", signedIn(t, "a@example.com")); rec.Code == http.StatusOK {
		t.Error("API answered at the domain root while mounted under a sub-path")
	}
}

func TestOAuthRedirectCarriesState(t *testing.T) {
	srv, _ := newServer(t, "")
	rec := do(srv, http.MethodGet, "/auth/google", "", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "accounts.google.com") || !strings.Contains(loc, "state=") {
		t.Fatalf("redirect lacks a CSRF state: %s", loc)
	}
	var stateCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == oauthStateCookie {
			stateCookie = c
		}
	}
	if stateCookie == nil || stateCookie.Value == "" {
		t.Fatal("no state cookie set, so the callback cannot verify the handshake")
	}
}

func TestOAuthCallbackRejectsStateMismatch(t *testing.T) {
	srv, _ := newServer(t, "")
	r := httptest.NewRequest(http.MethodGet, "/auth/google/callback?code=abc&state=attacker", nil)
	r.AddCookie(&http.Cookie{Name: oauthStateCookie, Value: "genuine"})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, r)

	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "state_mismatch") {
		t.Fatalf("status %d -> %q, want a redirect reporting state_mismatch", rec.Code, rec.Header().Get("Location"))
	}
}

func TestInitialsFor(t *testing.T) {
	for _, tc := range []struct{ name, email, want string }{
		{"Ajey Gore", "x@y.z", "AG"},
		{"ada lovelace", "x@y.z", "AL"},
		{"Jean Baptiste Emanuel Zorg", "x@y.z", "JB"},
		{"Prince", "x@y.z", "P"},
		{"Ólafur Árnason", "x@y.z", "ÓÁ"},
		// Google returns no name for some accounts, so the address is the
		// fallback — and the domain must not leak into the initials.
		{"", "ajey.gore@tnkrhaus.dev", "AG"},
		{"", "ajey@tnkrhaus.dev", "A"},
		{"", "first_last@example.com", "FL"},
		{"", "first-last@example.com", "FL"},
		{"", "user+tag@example.com", "UT"},
		{"", "", "?"},
		{"   ", "", "?"},
		{"...", "", "?"},
	} {
		if got := initialsFor(session.User{Name: tc.name, Email: tc.email}); got != tc.want {
			t.Errorf("initialsFor(%q,%q) = %q, want %q", tc.name, tc.email, got, tc.want)
		}
	}
}

// A template that fails halfway renders "template error" into the page with a
// 200, which no header or status assertion catches. These assert the pages
// actually come out whole.
func TestLoginPageRenders(t *testing.T) {
	srv, _ := newServer(t, "")
	rec := do(srv, http.MethodGet, "/", "", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("template failed to execute:\n%s", body)
	}
	for _, want := range []string{
		"Sign in with Google",
		"What Google shares with us",
		"Encrypted before it leaves your device",
		"/auth/google",
		// Carried over from the pre-rewrite landing page; asserted so a future
		// change cannot drop it silently the way the rewrite nearly did.
		"Open source, and built to know nothing",
		"github.com/ajeygore/sharetext",
		"</html>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("login page missing %q", want)
		}
	}
}

func TestAppPageRenders(t *testing.T) {
	srv, _ := newServer(t, "")
	rec := do(srv, http.MethodGet, "/", "", signedIn(t, "ajey.gore@example.com"))

	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("template failed to execute:\n%s", body)
	}
	for _, want := range []string{
		"Share text", "Read shared text", "Your shares",
		"Open source",
		"ajey.gore@example.com",
		">AG<", // initials fallback, since this session has no picture
		"</html>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("app page missing %q", want)
		}
	}
}

func TestErrorMessageIsRendered(t *testing.T) {
	srv, _ := newServer(t, "")
	body := do(srv, http.MethodGet, "/?error=state_mismatch", "", nil).Body.String()
	if !strings.Contains(body, "could not be verified") {
		t.Errorf("sign-in error not shown to the user:\n%s", body)
	}
	// An unknown code must not be reflected into the page verbatim.
	body = do(srv, http.MethodGet, "/?error=<script>alert(1)</script>", "", nil).Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("unknown error code was reflected into the page unescaped")
	}
}

// The landing page previously advertised "React + TypeScript" and "Bun", which
// the Go rewrite made false. Advertising the wrong stack on a security tool's
// front page is a credibility problem, not a cosmetic one.
func TestLandingStackIsAccurate(t *testing.T) {
	srv, _ := newServer(t, "")
	body := do(srv, http.MethodGet, "/", "", nil).Body.String()

	for _, want := range []string{"Go", "HTML · Tailwind", "Redis", "AES-256-GCM"} {
		if !strings.Contains(body, want) {
			t.Errorf("landing page does not mention %q", want)
		}
	}
	for _, gone := range []string{"React", "Bun", "TypeScript", "Vite"} {
		if strings.Contains(body, gone) {
			t.Errorf("landing page still advertises %q, which this app no longer uses", gone)
		}
	}
}

// The share message is composed in the browser but its URL comes from the
// server, so the page has to carry it. Hardcoding it in the JS would send
// every self-hosted instance's users to share.tnkrhaus.dev.
func TestAppPageCarriesTheAppURL(t *testing.T) {
	srv, _ := newServer(t, "")
	body := do(srv, http.MethodGet, "/", "", signedIn(t, "a@example.com")).Body.String()
	if !strings.Contains(body, `data-app-url="http://localhost:3000"`) {
		t.Errorf("app page does not carry the app URL for the share message:\n%s", body[:600])
	}
}

func TestAppURLIncludesBasePath(t *testing.T) {
	srv, _ := newServer(t, "/sharetext")
	body := do(srv, http.MethodGet, "/sharetext/", "", signedIn(t, "a@example.com")).Body.String()
	if !strings.Contains(body, `data-app-url="http://localhost:3000/sharetext"`) {
		t.Errorf("sub-path deployment advertises the wrong URL")
	}
}

// Nothing may hardcode the production hostname — that is what makes a
// self-hosted instance send its users to somebody else's server.
func TestNoHardcodedProductionHostInAssets(t *testing.T) {
	for _, name := range []string{
		"static/js/message.mjs", "static/js/app.mjs", "static/js/crypto.mjs",
		"templates/app.html",
	} {
		b, err := web.Static.ReadFile(name)
		if err != nil {
			if b, err = web.Templates.ReadFile(name); err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
		}
		if strings.Contains(string(b), "share.tnkrhaus.dev") {
			t.Errorf("%s hardcodes the production hostname", name)
		}
	}
}

// A copy button bound to a mistyped element id fails silently — the click does
// nothing and nobody notices until someone pastes an empty message. Assert the
// ids the script reaches for actually exist on the page.
func TestShareMessageElementsExist(t *testing.T) {
	srv, _ := newServer(t, "")
	body := do(srv, http.MethodGet, "/", "", signedIn(t, "a@example.com")).Body.String()

	for _, id := range []string{`id="share-message"`, `id="copy-message"`, `id="share-key"`} {
		if !strings.Contains(body, id) {
			t.Errorf("app page is missing %s", id)
		}
	}

	script, err := web.Static.ReadFile("static/js/app.mjs")
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{`"copy-message", "share-message"`, "composeShareMessage"} {
		if !strings.Contains(string(script), ref) {
			t.Errorf("app.mjs does not reference %s", ref)
		}
	}
}
