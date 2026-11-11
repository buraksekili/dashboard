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
	"strings"
	"testing"
)

func TestValidateAdditionalRedirectURIs(t *testing.T) {
	testCases := []struct {
		name        string
		uris        []string
		expectedErr string
	}{
		{
			name: "no entries",
		},
		{
			name: "canonical origins",
			uris: []string{"https://kkp-proxy.example.com", "https://kkp-internal.example.com:8443/"},
		},
		{
			name:        "entry with a path",
			uris:        []string{"https://kkp-proxy.example.com/api/v2/auth/callback"},
			expectedErr: `invalid -oidc-issuer-additional-redirect-uris entry "https://kkp-proxy.example.com/api/v2/auth/callback": must not contain a path, only scheme, host and optional port`,
		},
		{
			name:        "entry with an explicit default port",
			uris:        []string{"https://kkp-proxy.example.com", "https://kkp-port.example.com:443"},
			expectedErr: `invalid -oidc-issuer-additional-redirect-uris entry "https://kkp-port.example.com:443": must be written in canonical form as "https://kkp-port.example.com" (lower case, without the default port)`,
		},
		{
			name:        "entry with user info",
			uris:        []string{"https://user@kkp-proxy.example.com"},
			expectedErr: `invalid -oidc-issuer-additional-redirect-uris entry "https://user@kkp-proxy.example.com": must not contain user info`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			o := serverRunOptions{
				serviceAccountSigningKey:         strings.Repeat("k", 32),
				oidcIssuerAdditionalRedirectURIs: tc.uris,
			}
			err := o.validate()
			if tc.expectedErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil || err.Error() != tc.expectedErr {
				t.Fatalf("expected error %q, got %v", tc.expectedErr, err)
			}
		})
	}
}
