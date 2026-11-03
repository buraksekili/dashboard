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
	"slices"
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

func TestRejectIssuerAudienceOnLogin(t *testing.T) {
	tests := []struct {
		name            string
		clientID        string
		clientSecret    string
		issuerClientID  string
		wantSeparate    bool
		wantRejectedAud []string
	}{
		{
			name:           "default shared client",
			clientID:       "kubermaticIssuer",
			issuerClientID: "kubermaticIssuer",
		},
		{
			name:           "secret set but client IDs equal",
			clientID:       "kubermaticIssuer",
			clientSecret:   "s",
			issuerClientID: "kubermaticIssuer",
		},
		{
			name:           "different IDs without a secret",
			clientID:       "kubermatic",
			issuerClientID: "kubermaticIssuer",
		},
		{
			name:            "separate login client",
			clientID:        "kubermatic",
			clientSecret:    "s",
			issuerClientID:  "kubermaticIssuer",
			wantSeparate:    true,
			wantRejectedAud: []string{"kubermaticIssuer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := &authtypes.OIDCConfiguration{URL: "https://dex.example.com", ClientID: tt.issuerClientID}
			o := serverRunOptions{
				oidcAuthenticatorClientID:      tt.clientID,
				oidcAuthenticatorClientSecret:  tt.clientSecret,
				oidcIssuerClientID:             tt.issuerClientID,
				oidcIssuerConfiguration:        issuer,
				oidcAuthenticatorConfiguration: &authtypes.OIDCConfiguration{URL: issuer.URL, ClientID: tt.clientID},
				oidcLoginConfiguration:         buildOIDCLoginConfiguration(issuer, tt.clientID, tt.clientSecret),
			}

			o.rejectIssuerAudienceOnLogin()

			if got := o.separateLoginClientConfigured(); got != tt.wantSeparate {
				t.Fatalf("separateLoginClientConfigured() = %v, want %v", got, tt.wantSeparate)
			}
			if !slices.Equal(o.oidcAuthenticatorConfiguration.RejectedAudiences, tt.wantRejectedAud) {
				t.Errorf("authenticator RejectedAudiences = %v, want %v", o.oidcAuthenticatorConfiguration.RejectedAudiences, tt.wantRejectedAud)
			}
			if o.oidcLoginConfiguration != nil && !slices.Equal(o.oidcLoginConfiguration.RejectedAudiences, tt.wantRejectedAud) {
				t.Errorf("login RejectedAudiences = %v, want %v", o.oidcLoginConfiguration.RejectedAudiences, tt.wantRejectedAud)
			}
			if !slices.Equal(issuer.RejectedAudiences, nil) {
				t.Errorf("issuer configuration must keep accepting its own audience, got %v", issuer.RejectedAudiences)
			}
		})
	}
}
