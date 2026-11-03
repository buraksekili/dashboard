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

package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"k8c.io/dashboard/v2/pkg/handler/auth"
	authtypes "k8c.io/dashboard/v2/pkg/provider/auth/types"
)

// signingIssuer is a minimal OIDC provider that serves discovery and its signing key.
type signingIssuer struct {
	*httptest.Server
	signer jose.Signer
}

func newSigningIssuer(t *testing.T) *signingIssuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: key, KeyID: "k1", Algorithm: string(jose.RS256), Use: "sig"}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, nil)
	if err != nil {
		t.Fatal(err)
	}

	issuer := &signingIssuer{signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer.URL,
			"authorization_endpoint": issuer.URL + "/auth",
			"token_endpoint":         issuer.URL + "/token",
			"jwks_uri":               issuer.URL + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk.Public()}})
	})
	issuer.Server = httptest.NewServer(mux)
	t.Cleanup(issuer.Close)

	return issuer
}

func (s *signingIssuer) token(t *testing.T, aud []string, azp string) string {
	t.Helper()

	claims := map[string]interface{}{
		"iss":   s.URL,
		"sub":   "alice",
		"aud":   aud,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"email": "alice@example.com",
	}
	if azp != "" {
		claims["azp"] = azp
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := s.signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	return raw
}

func TestVerifyRejectedAudiences(t *testing.T) {
	issuer := newSigningIssuer(t)

	tests := []struct {
		name      string
		rejected  []string
		aud       []string
		azp       string
		wantError string
	}{
		{
			name: "login client token, nothing rejected",
			aud:  []string{"kubermatic"},
		},
		{
			name:     "login client token with separate login client",
			rejected: []string{"kubermaticIssuer"},
			aud:      []string{"kubermatic"},
			azp:      "kubermatic",
		},
		{
			name:      "token for login and issuer client together",
			rejected:  []string{"kubermaticIssuer"},
			aud:       []string{"kubermatic", "kubermaticIssuer"},
			wantError: `audience "kubermaticIssuer" is not accepted`,
		},
		{
			name:      "token the issuer client requested for the login client",
			rejected:  []string{"kubermaticIssuer"},
			aud:       []string{"kubermatic"},
			azp:       "kubermaticIssuer",
			wantError: `authorized party "kubermaticIssuer" is not accepted`,
		},
		{
			name:      "issuer client token",
			rejected:  []string{"kubermaticIssuer"},
			aud:       []string{"kubermaticIssuer"},
			wantError: "expected audience",
		},
		{
			name: "shared client keeps today's behaviour",
			aud:  []string{"kubermatic", "kubermaticIssuer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := auth.NewOpenIDClient(&authtypes.OIDCConfiguration{
				URL:               issuer.URL,
				ClientID:          "kubermatic",
				RejectedAudiences: tt.rejected,
			}, "", nil, nil)
			if err != nil {
				t.Fatal(err)
			}

			claims, err := client.Verify(context.Background(), issuer.token(t, tt.aud, tt.azp))
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if claims.Email != "alice@example.com" {
					t.Fatalf("unexpected email %q", claims.Email)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("expected error containing %q, got %v", tt.wantError, err)
			}
		})
	}
}
