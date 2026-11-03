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
	"testing"
	"time"
)

func TestUserRateLimiterAllowsBurstThenRefuses(t *testing.T) {
	limiter := NewUserRateLimiter()
	now := time.Now()

	for range exportBurst {
		if !limiter.allow("user-1", now) {
			t.Fatal("exports within the burst must be allowed")
		}
	}

	if limiter.allow("user-1", now) {
		t.Error("export above the burst must be refused")
	}

	// another user has their own budget
	if !limiter.allow("user-2", now) {
		t.Error("another user must not be affected")
	}

	// the budget refills over time
	if !limiter.allow("user-1", now.Add(2*exportInterval)) {
		t.Error("the budget must refill over time")
	}
}

func TestUserRateLimiterPrunesIdleUsers(t *testing.T) {
	limiter := NewUserRateLimiter()
	now := time.Now()

	// user-2 went idle long ago, user-3 is active
	limiter.allow("user-2", now.Add(-limiterIdleTTL-time.Minute))
	limiter.allow("user-3", now)

	// a map above the prune threshold prunes idle entries on the next allow
	limiterPruneSize = 1
	t.Cleanup(func() { limiterPruneSize = 1024 })

	limiter.allow("user-3", now)

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if _, exists := limiter.limiters["user-2"]; exists {
		t.Error("the idle limiter of user-2 must have been pruned")
	}
	if _, exists := limiter.limiters["user-3"]; !exists {
		t.Error("the active limiter of user-3 must stay")
	}
}
