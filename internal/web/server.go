// Package web is ShareText's HTTP surface: server-rendered pages, the small
// JSON API the browser calls, and Google sign-in.
//
// Note what this package does not do: decrypt. It moves opaque ciphertext
// between the browser and Redis and counts reads. The key never arrives here.
package web

import (
	"context"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/ajeygore/sharetext/internal/config"
	"github.com/ajeygore/sharetext/internal/session"
	"github.com/ajeygore/sharetext/internal/store"
	"github.com/ajeygore/sharetext/web"
)

const (
	maxPlaintextBytes = 64 * 1024
	// The server cannot see plaintext length, so it bounds the encoded payload:
	// 64 KB plus a 16-byte GCM tag, base64-expanded, plus slack.
	maxCiphertextChars = (maxPlaintextBytes+16)*4/3 + 256
	maxViewsLimit      = 10
	revealRateLimit    = 30
	oauthStateCookie   = "sharetext_oauth_state"
)

var (
	b64uPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	uuidV4       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	allowedTTLs  = map[int]string{300: "5 minutes", 3600: "1 hour", 86400: "24 hours", 604800: "7 days"}
	ttlOrder     = []int{300, 3600, 86400, 604800}
	notFoundBody = map[string]string{"error": "This text is no longer available."}
)

// Server holds everything the handlers need.
type Server struct {
	cfg   config.Config
	store *store.Store
	sess  *session.Manager
	tmpl  *template.Template
}

// New builds the server and parses templates once at startup, so a broken
// template fails the process rather than the first request that hits it.
func New(cfg config.Config, st *store.Store) (*Server, error) {
	tmpl, err := template.ParseFS(web.Templates, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:   cfg,
		store: st,
		sess:  session.New(cfg.SessionSecret, cfg.CookiePath(), cfg.SecureCookies()),
		tmpl:  tmpl,
	}, nil
}

// Handler returns the fully wired handler, mounted at the configured base path.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /up", s.handleHealth)
	mux.HandleFunc("GET /auth/google", s.handleGoogleStart)
	mux.HandleFunc("GET /auth/google/callback", s.handleGoogleCallback)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("POST /auth/dev-login", s.handleDevLogin)

	mux.HandleFunc("GET /api/me", s.handleMe)
	mux.HandleFunc("POST /api/paste", s.requireLogin(s.handleCreate))
	mux.HandleFunc("POST /api/paste/{id}/reveal", s.requireLogin(s.handleReveal))
	mux.HandleFunc("GET /api/paste/mine", s.requireLogin(s.handleMine))

	static, _ := fs.Sub(web.Static, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheForever(http.FileServer(http.FS(static)))))

	mux.HandleFunc("GET /", s.handleIndex)

	var h http.Handler = mux
	if s.cfg.BasePath != "" {
		h = mountUnder(s.cfg.BasePath, mux)
	}
	return securityHeaders(h)
}

// mountUnder serves mux beneath prefix and redirects the bare domain root to
// it, so nothing inside the app has to know its own mount point.
func mountUnder(prefix string, mux http.Handler) http.Handler {
	stripped := http.StripPrefix(prefix, mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == prefix || r.URL.Path == prefix+"/":
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			mux.ServeHTTP(w, r2)
		case strings.HasPrefix(r.URL.Path, prefix+"/"):
			stripped.ServeHTTP(w, r)
		case r.URL.Path == "/":
			http.Redirect(w, r, prefix+"/", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	})
}

func securityHeaders(next http.Handler) http.Handler {
	// Google rotates avatars across lh3-lh6, so the wildcard is load-bearing:
	// pinning one host blocks pictures for some accounts and not others.
	const csp = "default-src 'self'; script-src 'self'; style-src 'self'; " +
		"img-src 'self' data: https://*.googleusercontent.com; connect-src 'self'; " +
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		// Decrypted text must never ride along in a Referer to anywhere.
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// Vite content-hashes nothing here, so assets are revalidated rather than
// pinned forever; the pages themselves must never be cached.
func cacheForever(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		next.ServeHTTP(w, r)
	})
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) requireLogin(next func(http.ResponseWriter, *http.Request, session.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.sess.Get(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "Sign in with Google to continue.")
			return
		}
		next(w, r, u)
	}
}

func (s *Server) url(suffix string) string {
	if s.cfg.BasePath == "" {
		return "/" + strings.TrimPrefix(suffix, "/")
	}
	return s.cfg.BasePath + "/" + strings.TrimPrefix(suffix, "/")
}

// ---------- pages ----------

type pageData struct {
	BasePath     string
	User         *session.User
	Google       bool
	DevLogin     bool
	ErrorMessage string
	Initials     string
	TTLs         []ttlOption
	MaxViews     []int
	Features     []feature
}

type ttlOption struct {
	Seconds int
	Label   string
}

type feature struct {
	Title, Body, Icon string
}

var landingFeatures = []feature{
	{"Encrypted before it leaves your device",
		"Your text is encrypted in this browser with AES-256-GCM. The server only ever receives bytes it has no key for.",
		"M12 2 4 5.5v5.2c0 4.6 3.2 8.9 8 10.3 4.8-1.4 8-5.7 8-10.3V5.5L12 2Z"},
	{"Reads are counted, then it's gone",
		"Choose how many times it can be opened. On the last read the record is deleted outright — not flagged, deleted.",
		"M12 7v5l3.5 2M21 12a9 9 0 1 1-9-9 9 9 0 0 1 9 9Z"},
	{"Nothing left to clean up",
		"Everything carries an expiry. Whatever isn't read in time removes itself without anyone having to remember.",
		"M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13M10 11v6M14 11v6"},
}

// Sign-in failures are reported as codes in the URL so the callback never has
// to carry a message; they are turned into something readable here.
var authErrors = map[string]string{
	"state_mismatch":        "That sign-in attempt could not be verified. Please try again.",
	"token_exchange_failed": "Google could not complete the sign-in. Please try again.",
	"profile_fetch_failed":  "Could not read your Google profile. Please try again.",
	"unverified_email":      "Your Google email address is not verified, so we can't sign you in.",
	"authorization_failed":  "Sign-in was cancelled.",
	"access_denied":         "Sign-in was cancelled.",
	"oauth_failed":          "Sign-in failed. Please try again.",
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data := pageData{
		BasePath: s.cfg.BasePath,
		Google:   s.cfg.GoogleConfigured(),
		DevLogin: s.cfg.AllowDevLogin,
		Features: landingFeatures,
	}
	if code := r.URL.Query().Get("error"); code != "" {
		if msg, ok := authErrors[code]; ok {
			data.ErrorMessage = msg
		} else {
			data.ErrorMessage = "Sign-in failed."
		}
	}
	for _, sec := range ttlOrder {
		data.TTLs = append(data.TTLs, ttlOption{Seconds: sec, Label: allowedTTLs[sec]})
	}
	for i := 1; i <= maxViewsLimit; i++ {
		data.MaxViews = append(data.MaxViews, i)
	}
	if u, ok := s.sess.Get(r); ok {
		data.User = &u
		data.Initials = initialsFor(u)
	}

	name := "login.html"
	if data.User != nil {
		name = "app.html"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	redisOK := s.store.Ping(ctx) == nil
	status := http.StatusOK
	if !redisOK {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]any{
		"status": map[bool]string{true: "ok", false: "degraded"}[redisOK],
		"redis":  redisOK,
		// True only means credentials are present. It cannot tell you whether
		// the redirect URI is registered with Google.
		"google": s.cfg.GoogleConfigured(),
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u, ok := s.sess.Get(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": u})
}

// initialsFor gives up to two initials from whatever identity we have.
//
// Plenty of Google accounts have no picture, and the ones that do are served
// from rotating hosts a request can still fail against. Either way a bare
// avatar leaves a blank gap that reads as a broken page rather than an account
// without a photo. Splits on the separators that appear in display names and
// in the local part of an address, so "ajey.gore@example.com" gives AG.
func initialsFor(u session.User) string {
	source := strings.TrimSpace(u.Name)
	if source == "" {
		source = strings.TrimSpace(u.Email)
	}
	if local, _, found := strings.Cut(source, "@"); found {
		source = local
	}

	parts := strings.FieldsFunc(source, func(r rune) bool {
		return r == ' ' || r == '.' || r == '_' || r == '-' || r == '+'
	})
	var out []rune
	for _, part := range parts {
		if len(out) == 2 {
			break
		}
		out = append(out, unicode.ToUpper([]rune(part)[0]))
	}
	if len(out) == 0 {
		return "?"
	}
	return string(out)
}

// ---------- paste API ----------

type createRequest struct {
	CT         string `json:"ct"`
	IV         string `json:"iv"`
	MaxViews   int    `json:"max_views"`
	TTLSeconds int    `json:"ttl_seconds"`
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request, u session.User) {
	var req createRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCiphertextChars*2)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "Malformed request body.")
		return
	}

	// The server cannot inspect the plaintext, so it validates the envelope:
	// shape, encoding and size are the only things it is in a position to check.
	switch {
	case req.CT == "" || !b64uPattern.MatchString(req.CT):
		writeErr(w, http.StatusBadRequest, "Invalid ciphertext.")
		return
	case len(req.CT) > maxCiphertextChars:
		writeErr(w, http.StatusRequestEntityTooLarge, "Text is too large (64 KB maximum).")
		return
	case req.IV == "" || !b64uPattern.MatchString(req.IV) || len(req.IV) > 32:
		writeErr(w, http.StatusBadRequest, "Invalid IV.")
		return
	case req.MaxViews < 1 || req.MaxViews > maxViewsLimit:
		writeErr(w, http.StatusBadRequest, "Views must be between 1 and 10.")
		return
	}
	if _, ok := allowedTTLs[req.TTLSeconds]; !ok {
		writeErr(w, http.StatusBadRequest, "Invalid expiry.")
		return
	}

	id, expires, err := s.store.Create(r.Context(), store.CreateArgs{
		Ciphertext: req.CT, IV: req.IV, MaxViews: req.MaxViews,
		TTL: time.Duration(req.TTLSeconds) * time.Second, CreatedBy: u.Email,
	})
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "Could not store the text. Try again.")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "expires_at": expires.Format(time.RFC3339), "max_views": req.MaxViews,
	})
}

func (s *Server) handleReveal(w http.ResponseWriter, r *http.Request, u session.User) {
	if !s.store.AllowReveal(r.Context(), u.Email, revealRateLimit) {
		writeErr(w, http.StatusTooManyRequests, "Too many attempts. Wait a minute and try again.")
		return
	}

	// "Never existed", "expired", "used up" and "not even a valid id" all answer
	// identically. Distinguishing them would confirm to a prober that a given
	// id was once real, and leak the timing of other people's reads.
	id := r.PathValue("id")
	if !uuidV4.MatchString(id) {
		writeJSON(w, http.StatusNotFound, notFoundBody)
		return
	}

	got, err := s.store.Reveal(r.Context(), id, u.Email)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "Could not retrieve the text. Try again.")
		return
	}
	if got == nil {
		writeJSON(w, http.StatusNotFound, notFoundBody)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ct": got.Ciphertext, "iv": got.IV, "views_remaining": got.ViewsRemaining,
	})
}

func (s *Server) handleMine(w http.ResponseWriter, r *http.Request, u session.User) {
	list, err := s.store.ListByUser(r.Context(), u.Email)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "Could not load your history.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"pastes": list})
}
