/*
Copyright 2026 The Kubermatic Kubernetes Platform contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package userclustertoken

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	// exportBurst and exportInterval allow five exports at once per user, then one per minute.
	exportBurst    = 5
	exportInterval = time.Minute

	// limiterIdleTTL is how long an unused per-user limiter is kept; after that the user
	// has a full burst again anyway.
	limiterIdleTTL = exportInterval * exportBurst
)

// limiterPruneSize is the map size above which idle limiters are removed.
// A variable so tests can lower it.
var limiterPruneSize = 1024

// userRateLimiter limits token exports per user within one KKP API replica.
type userRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*limiterEntry
	every    rate.Limit
	burst    int
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewUserRateLimiter creates the per-user export rate limiter.
func NewUserRateLimiter() *userRateLimiter {
	return &userRateLimiter{
		limiters: map[string]*limiterEntry{},
		every:    rate.Every(exportInterval),
		burst:    exportBurst,
	}
}

// allow reports whether the user may export a token at the given time.
func (u *userRateLimiter) allow(user string, now time.Time) bool {
	u.mu.Lock()
	defer u.mu.Unlock()

	if len(u.limiters) > limiterPruneSize {
		for key, entry := range u.limiters {
			if now.Sub(entry.lastSeen) > limiterIdleTTL {
				delete(u.limiters, key)
			}
		}
	}

	entry, ok := u.limiters[user]
	if !ok {
		entry = &limiterEntry{limiter: rate.NewLimiter(u.every, u.burst)}
		u.limiters[user] = entry
	}
	entry.lastSeen = now

	return entry.limiter.AllowN(now, 1)
}
