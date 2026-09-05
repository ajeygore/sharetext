// Package session holds the signed-cookie session.
//
// The cookie is the user record. Everything ShareText needs about a signed-in
// person — email, name, avatar — fits in it, and pastes are keyed by email, so
// there is no user table and one less datastore to run and secure.
package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const (
	cookieName = "sharetext_session"
	maxAge     = 7 * 24 * time.Hour
)

// User is what a session carries.
type User struct {
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

// Manager signs and verifies session cookies.
type Manager struct {
	secret []byte
	path   string
	secure bool
}

// New returns a Manager. secure should be true only when the app is served
// over TLS — setting Secure on plain-HTTP localhost makes the browser drop the
// cookie and the login loop never closes.
func New(secret, path string, secure bool) *Manager {
	if path == "" {
		path = "/"
	}
	return &Manager{secret: []byte(secret), path: path, secure: secure}
}

func (m *Manager) sign(payload []byte) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Set writes the session cookie.
func (m *Manager) Set(w http.ResponseWriter, u User) error {
	payload, err := json.Marshal(u)
	if err != nil {
		return err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    encoded + "." + m.sign([]byte(encoded)),
		Path:     m.path,
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(maxAge.Seconds()),
	})
	return nil
}

// Get returns the session, or false if there is none, the signature does not
// verify, or the payload is unreadable — all of which mean "not signed in".
func (m *Manager) Get(r *http.Request) (User, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return User{}, false
	}
	encoded, sig, ok := strings.Cut(c.Value, ".")
	if !ok || encoded == "" || sig == "" {
		return User{}, false
	}
	// Constant time: a byte-by-byte comparison leaks how much of a forged
	// signature was correct, which is enough to forge one a byte at a time.
	if subtle.ConstantTimeCompare([]byte(sig), []byte(m.sign([]byte(encoded)))) != 1 {
		return User{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return User{}, false
	}
	var u User
	if err := json.Unmarshal(payload, &u); err != nil || u.Email == "" {
		return User{}, false
	}
	return u, true
}

// Clear expires the cookie.
func (m *Manager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: "", Path: m.path,
		HttpOnly: true, Secure: m.secure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}
