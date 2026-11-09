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

package main

import (
	"testing"

	"github.com/gorilla/securecookie"

	"k8c.io/dashboard/v2/pkg/handler/test"
	authtypes "k8c.io/dashboard/v2/pkg/provider/auth/types"
)

func TestBuildOIDCLoginConfiguration(t *testing.T) {
	issuer := &authtypes.OIDCConfiguration{
		URL:                  "https://dex.example.com",
		ClientID:             "kubermaticIssuer",
		ClientSecret:         "issuer-secret",
		SecureCookie:         securecookie.New([]byte("hash-key"), nil),
		CookieSecureMode:     true,
		OfflineAccessAsScope: true,
		SkipTLSVerify:        true,
	}

	if cfg := buildOIDCLoginConfiguration(issuer, "kubermatic", ""); cfg != nil {
		t.Fatalf("expected nil login configuration without authenticator secret, got %+v", cfg)
	}

	cfg := buildOIDCLoginConfiguration(issuer, "kubermatic", "authenticator-secret")
	if cfg == nil {
		t.Fatal("expected login configuration, got nil")
	}
	if cfg.URL != issuer.URL {
		t.Errorf("URL = %q, want %q", cfg.URL, issuer.URL)
	}
	if cfg.ClientID != "kubermatic" {
		t.Errorf("ClientID = %q, want %q", cfg.ClientID, "kubermatic")
	}
	if cfg.ClientSecret != "authenticator-secret" {
		t.Errorf("ClientSecret = %q, want %q", cfg.ClientSecret, "authenticator-secret")
	}
	if cfg.SecureCookie != issuer.SecureCookie {
		t.Error("SecureCookie must be the issuer secure cookie")
	}
	if cfg.CookieSecureMode != issuer.CookieSecureMode || cfg.OfflineAccessAsScope != issuer.OfflineAccessAsScope || cfg.SkipTLSVerify != issuer.SkipTLSVerify {
		t.Errorf("cookie/offline/TLS settings not copied from issuer: %+v", cfg)
	}
}

func TestCreateOIDCLoginVerifierFallsBackToIssuer(t *testing.T) {
	issuerVerifier := &test.IssuerVerifier{}

	verifier, err := createOIDCLoginVerifier(serverRunOptions{}, issuerVerifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verifier != issuerVerifier {
		t.Fatal("expected the issuer verifier when no login configuration is set")
	}
}
