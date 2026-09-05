package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ajeygore/sharetext/internal/session"
)

const (
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
)

var oauthClient = &http.Client{Timeout: 10 * time.Second}

func (s *Server) handleGoogleStart(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.GoogleConfigured() {
		http.Error(w, "Google OAuth is not configured.", http.StatusServiceUnavailable)
		return
	}

	// CSRF defence for the handshake: a random state echoed back by Google and
	// matched against a short-lived cookie, so a third party cannot walk a
	// victim through a sign-in they did not start.
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "could not start sign-in", http.StatusInternalServerError)
		return
	}
	state := base64.RawURLEncoding.EncodeToString(b)

	http.SetCookie(w, &http.Cookie{
		Name: oauthStateCookie, Value: state, Path: s.cfg.CookiePath(),
		HttpOnly: true, Secure: s.cfg.SecureCookies(), SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})

	q := url.Values{
		"client_id":     {s.cfg.GoogleClientID},
		"redirect_uri":  {s.cfg.RedirectURI()},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"prompt":        {"select_account"},
		"state":         {state},
	}
	http.Redirect(w, r, googleAuthURL+"?"+q.Encode(), http.StatusFound)
}

func (s *Server) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	fail := func(reason string) {
		http.Redirect(w, r, s.url("")+"?error="+url.QueryEscape(reason), http.StatusFound)
	}

	expected, err := r.Cookie(oauthStateCookie)
	http.SetCookie(w, &http.Cookie{Name: oauthStateCookie, Value: "", Path: s.cfg.CookiePath(), MaxAge: -1})

	if e := r.URL.Query().Get("error"); e != "" {
		fail(e)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" {
		fail("authorization_failed")
		return
	}
	if err != nil || state == "" ||
		subtle.ConstantTimeCompare([]byte(state), []byte(expected.Value)) != 1 {
		fail("state_mismatch")
		return
	}

	token, err := s.exchangeCode(code)
	if err != nil {
		log.Printf("oauth: token exchange failed: %v", err)
		fail("token_exchange_failed")
		return
	}

	profile, err := s.fetchProfile(token)
	if err != nil {
		log.Printf("oauth: profile fetch failed: %v", err)
		fail("profile_fetch_failed")
		return
	}

	// An unverified Google address is not proof of control of that mailbox, and
	// pastes are attributed by email — so refuse it.
	if profile.Email == "" || (profile.EmailVerified != nil && !*profile.EmailVerified) {
		fail("unverified_email")
		return
	}

	name := profile.Name
	if name == "" {
		name = profile.Email
	}
	if err := s.sess.Set(w, session.User{
		Email: strings.ToLower(profile.Email), Name: name, Picture: profile.Picture,
	}); err != nil {
		fail("oauth_failed")
		return
	}
	http.Redirect(w, r, s.url(""), http.StatusFound)
}

func (s *Server) exchangeCode(code string) (string, error) {
	resp, err := oauthClient.PostForm(googleTokenURL, url.Values{
		"client_id":     {s.cfg.GoogleClientID},
		"client_secret": {s.cfg.GoogleClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {s.cfg.RedirectURI()},
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}

	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("no access token in response")
	}
	return body.AccessToken, nil
}

type googleProfile struct {
	Email         string `json:"email"`
	EmailVerified *bool  `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func (s *Server) fetchProfile(token string) (googleProfile, error) {
	req, err := http.NewRequest(http.MethodGet, googleUserInfoURL, nil)
	if err != nil {
		return googleProfile{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := oauthClient.Do(req)
	if err != nil {
		return googleProfile{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return googleProfile{}, fmt.Errorf("userinfo returned %d", resp.StatusCode)
	}

	var p googleProfile
	err = json.NewDecoder(resp.Body).Decode(&p)
	return p, err
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sess.Clear(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleDevLogin is a local-only bypass so the app can be exercised before
// Google credentials exist. Double-gated in config: it needs an explicit
// opt-in AND a non-production build.
func (s *Server) handleDevLogin(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.AllowDevLogin {
		writeErr(w, http.StatusNotFound, "Not available.")
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	if body.Email == "" {
		body.Email = "dev@localhost"
	}
	if err := s.sess.Set(w, session.User{Email: strings.ToLower(body.Email), Name: body.Email}); err != nil {
		writeErr(w, http.StatusInternalServerError, "Could not sign in.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
