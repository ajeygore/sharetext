package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const secret = "0123456789abcdef0123456789abcdef"

func TestRoundTrip(t *testing.T) {
	m := New(secret, "/", false)
	rec := httptest.NewRecorder()
	want := User{Email: "a@example.com", Name: "A Person", Picture: "https://x/y.png"}

	if err := m.Set(rec, want); err != nil {
		t.Fatalf("set: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	got, ok := m.Get(req)
	if !ok {
		t.Fatal("session did not survive the round trip")
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestCookieHardening(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := New(secret, "/", true).Set(rec, User{Email: "a@example.com"}); err != nil {
		t.Fatal(err)
	}
	c := rec.Result().Cookies()[0]
	if !c.HttpOnly {
		t.Error("cookie is not HttpOnly, so scripts can read the session")
	}
	if !c.Secure {
		t.Error("cookie is not Secure on an HTTPS origin")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
}

// A session cookie is the only thing standing between a visitor and someone
// else's history, so a forged or edited one must not authenticate.
func TestTamperedCookieIsRejected(t *testing.T) {
	m := New(secret, "/", false)
	rec := httptest.NewRecorder()
	if err := m.Set(rec, User{Email: "victim@example.com"}); err != nil {
		t.Fatal(err)
	}
	original := rec.Result().Cookies()[0].Value

	for name, value := range map[string]string{
		"truncated":     original[:len(original)-4],
		"flipped byte":  strings.Replace(original, string(original[3]), "Z", 1),
		"empty":         "",
		"no signature":  strings.SplitN(original, ".", 2)[0],
		"foreign value": "eyJlbWFpbCI6ImF0dGFja2VyQGV4YW1wbGUuY29tIn0.deadbeef",
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: value})
		if _, ok := m.Get(req); ok {
			t.Errorf("%s cookie was accepted", name)
		}
	}
}

func TestWrongSecretIsRejected(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := New(secret, "/", false).Set(rec, User{Email: "a@example.com"}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	if _, ok := New("ffffffffffffffffffffffffffffffff", "/", false).Get(req); ok {
		t.Fatal("a session signed with a different secret was accepted")
	}
}

func TestNoCookie(t *testing.T) {
	if _, ok := New(secret, "/", false).Get(httptest.NewRequest(http.MethodGet, "/", nil)); ok {
		t.Fatal("got a session with no cookie present")
	}
}

func TestClear(t *testing.T) {
	rec := httptest.NewRecorder()
	New(secret, "/", false).Clear(rec)
	c := rec.Result().Cookies()[0]
	if c.MaxAge >= 0 {
		t.Errorf("MaxAge = %d, want negative so the browser drops it", c.MaxAge)
	}
}
