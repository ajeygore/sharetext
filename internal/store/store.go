// Package store is ShareText's only persistence: ciphertext, a view counter,
// and an audit trail, all in Redis with a TTL.
//
// Nothing here can read a paste. The server never holds a key — encryption and
// decryption happen in the browser — so every value below is opaque bytes.
package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	logCap       = 20
	userListCap  = 50
	userListTTL  = 7 * 24 * time.Hour
	defaultAddr  = "127.0.0.1:6380"
	rateLimitTTL = 120 * time.Second
)

func testAddr() string {
	if a := os.Getenv("REDIS_ADDR"); a != "" {
		return a
	}
	return defaultAddr
}

// NewID returns a lowercase UUIDv4.
//
// Hand-rolled rather than pulled in as a dependency: it is a dozen lines of
// well-specified bit-twiddling, it is exhaustively tested here, and this is a
// security tool where every dependency is supply-chain surface.
//
// v4 and deliberately not v7. The standard prefers v7 for its index locality,
// but v7 embeds a creation timestamp — and when a given secret was created is
// precisely the metadata this application must not publish. Pastes are keyed
// in Redis, not indexed in a B-tree, so v7 buys nothing here anyway.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant

	var out [36]byte
	hex.Encode(out[0:8], b[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], b[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], b[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], b[8:10])
	out[23] = '-'
	hex.Encode(out[24:36], b[10:16])
	return string(out[:]), nil
}

// Options configures the Redis connection.
type Options struct {
	Addr string
}

// Store is the Redis-backed paste store.
type Store struct {
	rdb    *redis.Client
	reveal *redis.Script
}

// New connects to Redis. It does not dial until first use.
func New(opts Options) (*Store, error) {
	addr := opts.Addr
	if addr == "" {
		addr = defaultAddr
	}
	return &Store{
		rdb:    redis.NewClient(&redis.Options{Addr: addr, MaxRetries: 3}),
		reveal: redis.NewScript(revealLua),
	}, nil
}

func (s *Store) Close() error                   { return s.rdb.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.rdb.Ping(ctx).Err() }
func pasteKey(id string) string                 { return "paste:" + id }
func logKey(id string) string                   { return "paste:" + id + ":log" }
func userKey(email string) string               { return "user:" + strings.ToLower(email) + ":pastes" }
func rateKey(email string, bucket int64) string {
	return fmt.Sprintf("rl:%s:%d", strings.ToLower(email), bucket)
}

/*
Reveal is one Lua script, and it has to stay that way.

Read-then-decrement across two round trips is a race: two concurrent reveals of
a one-view paste would both read views=1, both return the ciphertext, and the
paste would be read twice. Redis runs scripts single-threaded to completion, so
bundling read + decrement + delete here makes over-releasing impossible however
many requests arrive at once.

The view is spent when the ciphertext is *released*, not when the browser
reports a successful decrypt — a client-sent confirmation is unenforceable,
since a malicious reader could simply never send one and read forever.
*/
const revealLua = `
local pkey, lkey = KEYS[1], KEYS[2]
local viewer, ts = ARGV[1], ARGV[2]

local views = redis.call('HGET', pkey, 'views')
if not views then return nil end

local ct = redis.call('HGET', pkey, 'ct')
local iv = redis.call('HGET', pkey, 'iv')
local remaining = tonumber(views) - 1
local ttl = redis.call('TTL', pkey)

-- The audit trail outlives the paste so the creator can still see who read it.
redis.call('RPUSH', lkey, ts .. ' ' .. viewer)
redis.call('LTRIM', lkey, -20, -1)
if ttl > 0 then redis.call('EXPIRE', lkey, ttl) end

if remaining <= 0 then
  redis.call('DEL', pkey)
else
  redis.call('HSET', pkey, 'views', remaining)
end

return { ct, iv, tostring(remaining) }
`

// CreateArgs is a new paste. Ciphertext and IV are base64url; the server has
// no way to interpret either.
type CreateArgs struct {
	Ciphertext string
	IV         string
	MaxViews   int
	TTL        time.Duration
	CreatedBy  string
}

type userEntry struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	MaxViews  int       `json:"max_views"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Create stores a paste and returns its id and expiry.
func (s *Store) Create(ctx context.Context, a CreateArgs) (string, time.Time, error) {
	id, err := NewID()
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now().UTC()
	expires := now.Add(a.TTL)

	entry, err := json.Marshal(userEntry{ID: id, CreatedAt: now, MaxViews: a.MaxViews, ExpiresAt: expires})
	if err != nil {
		return "", time.Time{}, err
	}

	pipe := s.rdb.TxPipeline()
	pipe.HSet(ctx, pasteKey(id), map[string]any{
		"ct":         a.Ciphertext,
		"iv":         a.IV,
		"views":      strconv.Itoa(a.MaxViews),
		"created_by": strings.ToLower(a.CreatedBy),
		"created_at": now.Format(time.RFC3339),
	})
	pipe.Expire(ctx, pasteKey(id), a.TTL)
	pipe.LPush(ctx, userKey(a.CreatedBy), entry)
	pipe.LTrim(ctx, userKey(a.CreatedBy), 0, userListCap-1)
	pipe.Expire(ctx, userKey(a.CreatedBy), userListTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", time.Time{}, fmt.Errorf("store paste: %w", err)
	}
	return id, expires, nil
}

// Revealed is a released paste.
type Revealed struct {
	Ciphertext     string
	IV             string
	ViewsRemaining int
}

// Reveal releases the ciphertext and spends one view, atomically. It returns
// nil when the paste does not exist, has expired, or is already used up —
// callers must not distinguish those cases to the outside world.
func (s *Store) Reveal(ctx context.Context, id, viewer string) (*Revealed, error) {
	res, err := s.reveal.Run(ctx, s.rdb,
		[]string{pasteKey(id), logKey(id)},
		strings.ToLower(viewer), time.Now().UTC().Format(time.RFC3339),
	).Result()

	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reveal: %w", err)
	}

	parts, ok := res.([]any)
	if !ok || len(parts) != 3 {
		return nil, fmt.Errorf("reveal: unexpected script result %T", res)
	}
	remaining, err := strconv.Atoi(fmt.Sprint(parts[2]))
	if err != nil {
		return nil, fmt.Errorf("reveal: bad remaining count: %w", err)
	}
	if remaining < 0 {
		remaining = 0
	}
	return &Revealed{
		Ciphertext:     fmt.Sprint(parts[0]),
		IV:             fmt.Sprint(parts[1]),
		ViewsRemaining: remaining,
	}, nil
}

// Summary is one row of a creator's history. ViewsRemaining is nil once the
// paste is gone.
type Summary struct {
	ID             string
	CreatedAt      time.Time
	MaxViews       int
	ExpiresAt      time.Time
	ViewsRemaining *int
	RevealedBy     []string
}

// ListByUser returns a creator's pastes, newest first.
func (s *Store) ListByUser(ctx context.Context, email string) ([]Summary, error) {
	raw, err := s.rdb.LRange(ctx, userKey(email), 0, userListCap-1).Result()
	if err != nil {
		return nil, fmt.Errorf("list pastes: %w", err)
	}

	entries := make([]userEntry, 0, len(raw))
	for _, r := range raw {
		var e userEntry
		if json.Unmarshal([]byte(r), &e) == nil {
			entries = append(entries, e)
		}
	}
	if len(entries) == 0 {
		return []Summary{}, nil
	}

	// One pipeline rather than 2N sequential round trips.
	pipe := s.rdb.Pipeline()
	views := make([]*redis.StringCmd, len(entries))
	logs := make([]*redis.StringSliceCmd, len(entries))
	for i, e := range entries {
		views[i] = pipe.HGet(ctx, pasteKey(e.ID), "views")
		logs[i] = pipe.LRange(ctx, logKey(e.ID), 0, -1)
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("list pastes: %w", err)
	}

	out := make([]Summary, 0, len(entries))
	for i, e := range entries {
		sum := Summary{
			ID: e.ID, CreatedAt: e.CreatedAt, MaxViews: e.MaxViews, ExpiresAt: e.ExpiresAt,
			RevealedBy: []string{},
		}
		if v, err := views[i].Result(); err == nil {
			if n, err := strconv.Atoi(v); err == nil {
				sum.ViewsRemaining = &n
			}
		}
		if l, err := logs[i].Result(); err == nil {
			sum.RevealedBy = l
		}
		out = append(out, sum)
	}
	return out, nil
}

// AllowReveal is a per-user, per-minute cap on reveal attempts. Paste ids are
// UUIDv4, so guessing one is already infeasible; this blunts hammering by a
// compromised account. It fails open — Redis being down should not lock people
// out, and the reveal itself will fail loudly anyway.
func (s *Store) AllowReveal(ctx context.Context, email string, limit int) bool {
	key := rateKey(email, time.Now().Unix()/60)
	n, err := s.rdb.Incr(ctx, key).Result()
	if err != nil {
		return true
	}
	if n == 1 {
		s.rdb.Expire(ctx, key, rateLimitTTL)
	}
	return int(n) <= limit
}
