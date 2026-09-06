// Package config reads ShareText's environment.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// Config is the whole runtime configuration.
type Config struct {
	Port               int
	BasePath           string
	PublicOrigin       string
	SessionSecret      string
	GoogleClientID     string
	GoogleClientSecret string
	RedisAddr          string
	Production         bool
	AllowDevLogin      bool
}

const minSecretLen = 32

// Load reads the environment.
func Load() (Config, error) {
	port, err := strconv.Atoi(env("PORT", "3000"))
	if err != nil {
		return Config{}, fmt.Errorf("PORT: %w", err)
	}
	production := os.Getenv("APP_ENV") == "production" || os.Getenv("NODE_ENV") == "production"

	c := Config{
		Port:               port,
		BasePath:           os.Getenv("BASE_PATH"),
		PublicOrigin:       env("PUBLIC_ORIGIN", fmt.Sprintf("http://localhost:%d", port)),
		SessionSecret:      os.Getenv("SESSION_SECRET"),
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedisAddr:          env("REDIS_ADDR", redisAddrFromParts()),
		Production:         production,
		// Double-gated: an explicit opt-in AND a non-production build, so it
		// cannot be switched on in production by environment alone.
		AllowDevLogin: os.Getenv("ALLOW_DEV_LOGIN") == "true" && !production,
	}.normalise()

	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	if c.SessionSecret == "" {
		// Ephemeral dev secret: sessions do not survive a restart, which is
		// fine locally and strictly better than a hardcoded default in the repo.
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return Config{}, err
		}
		c.SessionSecret = hex.EncodeToString(b)
		log.Println("SESSION_SECRET unset — using an ephemeral dev secret; sessions reset on restart.")
	}
	return c, nil
}

func (c Config) normalise() Config {
	c.PublicOrigin = strings.TrimRight(c.PublicOrigin, "/")
	c.BasePath = strings.TrimRight(c.BasePath, "/")
	if c.BasePath != "" && !strings.HasPrefix(c.BasePath, "/") {
		c.BasePath = "/" + c.BasePath
	}
	return c
}

// Validate rejects a configuration that would run insecurely.
func (c Config) Validate() error {
	if c.Production && len(c.SessionSecret) < minSecretLen {
		return errors.New("SESSION_SECRET must be at least 32 characters in production; generate one with: openssl rand -hex 32")
	}
	return nil
}

// SecureCookies reports whether the app is actually served over TLS. Cookies
// marked Secure on a plain-HTTP origin are dropped by the browser, which
// presents as a login loop that never closes.
func (c Config) SecureCookies() bool { return strings.HasPrefix(c.PublicOrigin, "https://") }

// GoogleConfigured reports whether credentials are present. It says nothing
// about whether the redirect URI is registered with Google — that can only be
// discovered by attempting a sign-in.
func (c Config) GoogleConfigured() bool {
	return c.GoogleClientID != "" && c.GoogleClientSecret != ""
}

// RedirectURI is the OAuth callback, which must match Google's registration
// character for character.
func (c Config) RedirectURI() string {
	return c.PublicOrigin + c.BasePath + "/auth/google/callback"
}

// AppURL is where this instance is reachable. The share message a creator
// pastes into chat advertises it, so it must come from the running server —
// hardcoding it would make every self-hosted instance send its users to
// somebody else's.
func (c Config) AppURL() string { return c.PublicOrigin + c.BasePath }

// CookiePath scopes cookies to the mount point so they are not sent to other
// apps sharing the domain.
func (c Config) CookiePath() string {
	if c.BasePath == "" {
		return "/"
	}
	return c.BasePath
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Defaults match docker-compose.yml, which publishes on 6380 rather than the
// conventional 6379 — that port is frequently already claimed by another
// project's Redis.
func redisAddrFromParts() string {
	host := env("REDIS_HOST", "127.0.0.1")
	port := env("REDIS_PORT", "6380")
	return host + ":" + port
}
