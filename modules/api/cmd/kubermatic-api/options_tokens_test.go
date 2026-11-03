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

	"k8c.io/kubermatic/v2/pkg/features"
)

// The export endpoint and the token management API register only when the
// feature gate is on and the dashboard login uses a client separate from the
// issuer client. Anything else must leave the endpoints away (404).
func TestUserClusterTokensEnabled(t *testing.T) {
	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		issuerClient string
		featureGates features.FeatureGate
		wantEnabled  bool
	}{
		{
			name:         "feature gate off",
			clientID:     "kubermatic",
			clientSecret: "s",
			issuerClient: "kubermaticIssuer",
			wantEnabled:  false,
		},
		{
			name:         "no separate login client",
			clientID:     "kubermaticIssuer",
			clientSecret: "s",
			issuerClient: "kubermaticIssuer",
			featureGates: features.FeatureGate{features.UserClusterTokenWebhook: true},
			wantEnabled:  false,
		},
		{
			name:         "separate client without secret",
			clientID:     "kubermatic",
			issuerClient: "kubermaticIssuer",
			featureGates: features.FeatureGate{features.UserClusterTokenWebhook: true},
			wantEnabled:  false,
		},
		{
			name:         "gate on and separate login client",
			clientID:     "kubermatic",
			clientSecret: "s",
			issuerClient: "kubermaticIssuer",
			featureGates: features.FeatureGate{features.UserClusterTokenWebhook: true},
			wantEnabled:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := serverRunOptions{
				oidcAuthenticatorClientID:     tt.clientID,
				oidcAuthenticatorClientSecret: tt.clientSecret,
				oidcIssuerClientID:            tt.issuerClient,
				featureGates:                  tt.featureGates,
			}

			if got := o.userClusterTokensEnabled(); got != tt.wantEnabled {
				t.Errorf("userClusterTokensEnabled() = %v, want %v", got, tt.wantEnabled)
			}
		})
	}
}
