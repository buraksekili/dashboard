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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"

	apiv1 "k8c.io/dashboard/v2/pkg/api/v1"
	"k8c.io/dashboard/v2/pkg/handler"
	"k8c.io/dashboard/v2/pkg/handler/auth"
	"k8c.io/dashboard/v2/pkg/handler/middleware"
	authtypes "k8c.io/dashboard/v2/pkg/provider/auth/types"
)

// fakeLoginVerifier accepts one bearer token as the test user.
type fakeLoginVerifier struct{}

func (fakeLoginVerifier) Verify(_ context.Context, token string) (authtypes.TokenClaims, error) {
	if token != "valid-login-token" {
		return authtypes.TokenClaims{}, errors.New("unknown token")
	}
	return authtypes.TokenClaims{
		Subject: "alice-subject",
		Email:   testUserEmail,
		Expiry:  apiv1.NewTime(time.Now().Add(time.Hour)),
	}, nil
}

// The token API must work through real HTTP routing with the shared server options:
// earlier its routes lacked the token extractor and every request failed with
// "not authorized" in the dashboard, which the endpoint-level tests could not see.
func TestTokenAPIOverHTTP(t *testing.T) {
	f := newTokenAPIFixture(t, nil, nil)
	f.api.tokenVerifiers = fakeLoginVerifier{}
	f.api.serverOpts = []httptransport.ServerOption{
		httptransport.ServerBefore(middleware.TokenExtractor(auth.NewHeaderBearerTokenExtractor("Authorization"))),
		httptransport.ServerErrorEncoder(handler.ErrorEncoder),
	}
	router := mux.NewRouter()
	f.api.Install(router)

	path := "/projects/" + testProjectID + "/clusters/" + testClusterID + "/kubeconfig/tokens"

	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer valid-login-token")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logged-in list: got %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, path, nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous list: got %d, want 401", rec.Code)
	}
	// the shared error encoder answers KKP JSON errors, not a plain-text body
	if !strings.Contains(rec.Header().Get("Content-Type"), "application/json") || !strings.Contains(rec.Body.String(), `"error"`) {
		t.Errorf("anonymous list: want a KKP JSON error, got %q %s", rec.Header().Get("Content-Type"), rec.Body.String())
	}
}
