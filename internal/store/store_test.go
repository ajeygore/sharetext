package store

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	owner  = "owner@example.com"
	viewer = "viewer@example.com"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(Options{Addr: testAddr()})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := s.Ping(context.Background()); err != nil {
		t.Skipf("Redis not reachable at %s (run `docker compose up -d`): %v", testAddr(), err)
	}
	t.Cleanup(func() {
		_ = s.FlushForTests(context.Background())
		_ = s.Close()
	})
	if err := s.FlushForTests(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return s
}

func create(t *testing.T, s *Store, maxViews int) string {
	t.Helper()
	id, _, err := s.Create(context.Background(), CreateArgs{
		Ciphertext: "Y2lwaGVydGV4dA",
		IV:         "aXZpdml2aXZpdg",
		MaxViews:   maxViews,
		TTL:        5 * time.Minute,
		CreatedBy:  owner,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return id
}

// UUIDv4, lowercase, with the version and variant nibbles pinned. v4 and not
// v7 on purpose: v7 embeds a timestamp, and when each secret was created is
// exactly the metadata a secret-sharing tool must not publish.
var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewIDIsUUIDv4(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatalf("NewID: %v", err)
		}
		if !uuidV4.MatchString(id) {
			t.Fatalf("id %q is not a lowercase UUIDv4", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}

func TestCreateStoresOnlyCiphertext(t *testing.T) {
	s := newTestStore(t)
	id := create(t, s, 1)

	fields, err := s.rawPaste(context.Background(), id)
	if err != nil {
		t.Fatalf("raw: %v", err)
	}
	want := map[string]bool{"ct": true, "iv": true, "views": true, "created_by": true, "created_at": true}
	for k := range fields {
		if !want[k] {
			t.Errorf("unexpected field %q stored", k)
		}
	}
	if fields["ct"] != "Y2lwaGVydGV4dA" {
		t.Errorf("ct = %q", fields["ct"])
	}
}

func TestCreateSetsTTL(t *testing.T) {
	s := newTestStore(t)
	id := create(t, s, 1)
	ttl, err := s.ttl(context.Background(), id)
	if err != nil {
		t.Fatalf("ttl: %v", err)
	}
	if ttl < 4*time.Minute+50*time.Second || ttl > 5*time.Minute {
		t.Fatalf("ttl = %v, want ~5m", ttl)
	}
}

func TestRevealCountsDownAndDeletes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := create(t, s, 3)

	for want := 2; want >= 0; want-- {
		got, err := s.Reveal(ctx, id, viewer)
		if err != nil {
			t.Fatalf("reveal: %v", err)
		}
		if got == nil {
			t.Fatalf("reveal returned nil with %d views left", want+1)
		}
		if got.ViewsRemaining != want {
			t.Fatalf("ViewsRemaining = %d, want %d", got.ViewsRemaining, want)
		}
	}

	got, err := s.Reveal(ctx, id, viewer)
	if err != nil {
		t.Fatalf("reveal: %v", err)
	}
	if got != nil {
		t.Fatal("paste was readable after its last view")
	}
	if exists, _ := s.exists(ctx, id); exists {
		t.Fatal("exhausted paste was not deleted")
	}
}

func TestRevealUnknownID(t *testing.T) {
	s := newTestStore(t)
	got, err := s.Reveal(context.Background(), "6ba7b810-9dad-11d1-80b4-00c04fd430c8", viewer)
	if err != nil {
		t.Fatalf("reveal: %v", err)
	}
	if got != nil {
		t.Fatal("unknown id returned a paste")
	}
}

func TestRevealRecordsViewerAndOutlivesPaste(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := create(t, s, 1)

	if _, err := s.Reveal(ctx, id, viewer); err != nil {
		t.Fatalf("reveal: %v", err)
	}
	log, err := s.log(ctx, id)
	if err != nil {
		t.Fatalf("log: %v", err)
	}
	if len(log) != 1 || !strings.Contains(log[0], viewer) {
		t.Fatalf("log = %v, want one entry naming %s", log, viewer)
	}
	if exists, _ := s.exists(ctx, id); exists {
		t.Fatal("paste should be gone but its log should remain")
	}
}

// The reason Reveal is a Lua script. Read-then-decrement over two round trips
// races: concurrent reveals of a one-read paste would all see views=1 and all
// succeed.
func TestRevealNeverOverReleases(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for _, concurrency := range []int{2, 10, 50} {
		if err := s.FlushForTests(ctx); err != nil {
			t.Fatal(err)
		}
		id := create(t, s, 1)

		var mu sync.Mutex
		var wg sync.WaitGroup
		succeeded := 0
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := s.Reveal(ctx, id, viewer)
				if err == nil && got != nil {
					mu.Lock()
					succeeded++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()

		if succeeded != 1 {
			t.Fatalf("concurrency %d: %d reveals succeeded, want exactly 1", concurrency, succeeded)
		}
	}
}

func TestRevealReleasesExactlyMaxViewsUnderStampede(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	id := create(t, s, 4)

	var mu sync.Mutex
	var wg sync.WaitGroup
	remaining := []int{}
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := s.Reveal(ctx, id, viewer)
			if err == nil && got != nil {
				mu.Lock()
				remaining = append(remaining, got.ViewsRemaining)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(remaining) != 4 {
		t.Fatalf("%d reveals succeeded, want 4", len(remaining))
	}
	seen := map[int]bool{}
	for _, r := range remaining {
		if seen[r] {
			t.Fatalf("duplicate ViewsRemaining %d — a decrement was lost", r)
		}
		seen[r] = true
	}
	for want := 0; want < 4; want++ {
		if !seen[want] {
			t.Errorf("no reveal reported %d remaining", want)
		}
	}
}

func TestListUserPastes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first := create(t, s, 1)
	second := create(t, s, 5)
	if _, err := s.Reveal(ctx, first, viewer); err != nil {
		t.Fatal(err)
	}

	list, err := s.ListByUser(ctx, owner)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 || list[0].ID != second || list[1].ID != first {
		t.Fatalf("list = %+v, want newest first", list)
	}
	if list[1].ViewsRemaining != nil {
		t.Errorf("consumed paste should report no remaining views, got %v", *list[1].ViewsRemaining)
	}
	if len(list[1].RevealedBy) != 1 {
		t.Errorf("consumed paste lost its audit trail: %v", list[1].RevealedBy)
	}
	if list[0].ViewsRemaining == nil || *list[0].ViewsRemaining != 5 {
		t.Errorf("live paste ViewsRemaining = %v, want 5", list[0].ViewsRemaining)
	}

	other, err := s.ListByUser(ctx, viewer)
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Errorf("one user's pastes leaked to another: %+v", other)
	}
}
