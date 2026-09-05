package store

import (
	"context"
	"time"
)

// Inspection helpers used by the tests. Kept in the package rather than the
// test file so they are available to any future test binary, and deliberately
// unexported so nothing outside can reach past the store's API.

func (s *Store) rawPaste(ctx context.Context, id string) (map[string]string, error) {
	return s.rdb.HGetAll(ctx, pasteKey(id)).Result()
}

func (s *Store) ttl(ctx context.Context, id string) (time.Duration, error) {
	return s.rdb.TTL(ctx, pasteKey(id)).Result()
}

func (s *Store) exists(ctx context.Context, id string) (bool, error) {
	n, err := s.rdb.Exists(ctx, pasteKey(id)).Result()
	return n > 0, err
}

func (s *Store) log(ctx context.Context, id string) ([]string, error) {
	return s.rdb.LRange(ctx, logKey(id), 0, -1).Result()
}

// FlushForTests removes every key this package owns.
func (s *Store) FlushForTests(ctx context.Context) error {
	for _, pattern := range []string{"paste:*", "user:*:pastes", "rl:*"} {
		keys, err := s.rdb.Keys(ctx, pattern).Result()
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			if err := s.rdb.Del(ctx, keys...).Err(); err != nil {
				return err
			}
		}
	}
	return nil
}
