// ShareText — share a piece of text that can only be read a set number of
// times, then destroys itself.
//
// The server is deliberately blind: text is encrypted in the browser, so this
// process only ever holds ciphertext it has no key for.
package main

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/ajeygore/sharetext/internal/config"
	"github.com/ajeygore/sharetext/internal/store"
	"github.com/ajeygore/sharetext/internal/web"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	st, err := store.New(store.Options{Addr: cfg.RedisAddr})
	if err != nil {
		log.Fatalf("redis: %v", err)
	}
	defer st.Close()

	srv, err := web.New(cfg, st)
	if err != nil {
		log.Fatalf("server: %v", err)
	}

	log.Printf("ShareText listening on :%d  ->  %s%s/", cfg.Port, cfg.PublicOrigin, cfg.BasePath)
	if !cfg.GoogleConfigured() {
		log.Println("Google OAuth is not configured — sign-in will be unavailable.")
	}
	if cfg.AllowDevLogin {
		log.Println("ALLOW_DEV_LOGIN is on — local sign-in bypass is enabled. Never in production.")
	}

	httpServer := &http.Server{
		Addr:              ":" + strconv.Itoa(cfg.Port),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
