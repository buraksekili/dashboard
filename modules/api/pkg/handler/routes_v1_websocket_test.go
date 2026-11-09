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

package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	authtypes "k8c.io/dashboard/v2/pkg/provider/auth/types"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type fakeTokenAuth struct {
	claims authtypes.TokenClaims
	err    error
}

func (f fakeTokenAuth) Extract(_ *http.Request) (string, error) {
	return "token", nil
}

func (f fakeTokenAuth) Verify(_ context.Context, _ string) (authtypes.TokenClaims, error) {
	return f.claims, f.err
}

func TestVerifyAuthorizationToken(t *testing.T) {
	testCases := []struct {
		name           string
		auth           fakeTokenAuth
		expectErr      bool
		expectedEmail  string
		expectedGroups []string
	}{
		{
			name:           "groups claim is returned",
			auth:           fakeTokenAuth{claims: authtypes.TokenClaims{Subject: "sub", Name: "Bob", Email: "Bob@Acme.com", Groups: []string{"devs", "admins"}}},
			expectedEmail:  "Bob@Acme.com",
			expectedGroups: []string{"devs", "admins"},
		},
		{
			name:          "no groups claim",
			auth:          fakeTokenAuth{claims: authtypes.TokenClaims{Subject: "sub", Email: "bob@acme.com"}},
			expectedEmail: "bob@acme.com",
		},
		{
			name:      "no subject",
			auth:      fakeTokenAuth{claims: authtypes.TokenClaims{Email: "bob@acme.com"}},
			expectErr: true,
		},
		{
			name:      "invalid token",
			auth:      fakeTokenAuth{err: errors.New("invalid")},
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ws/me", nil)
			user, err := verifyAuthorizationToken(req, tc.auth, tc.auth)
			if tc.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expectedEmail, user.Email)
			require.Equal(t, tc.expectedGroups, user.Groups)
		})
	}
}

func TestVerifyAuthorizationTokenClaimsKeepsRawClaims(t *testing.T) {
	raw := map[string]interface{}{"email": "bob@acme.com", "email_verified": false}
	auth := fakeTokenAuth{claims: authtypes.TokenClaims{Subject: "sub", Email: "bob@acme.com", Raw: raw}}

	claims, err := verifyAuthorizationTokenClaims(httptest.NewRequest(http.MethodGet, "/ws", nil), auth, auth)
	require.NoError(t, err)
	require.Equal(t, raw, claims.Raw)
}

func TestSeedOfDatacenter(t *testing.T) {
	seeds := map[string]*kubermaticv1.Seed{
		"a": {ObjectMeta: metav1.ObjectMeta{Name: "a"}, Spec: kubermaticv1.SeedSpec{Datacenters: map[string]kubermaticv1.Datacenter{"dc-a": {}}}},
		"b": {ObjectMeta: metav1.ObjectMeta{Name: "b"}, Spec: kubermaticv1.SeedSpec{Datacenters: map[string]kubermaticv1.Datacenter{"dc-b": {}}}},
	}
	getter := func() (map[string]*kubermaticv1.Seed, error) { return seeds, nil }

	require.Equal(t, "b", seedOfDatacenter(getter, "dc-b").Name)
	require.Nil(t, seedOfDatacenter(getter, "missing"))
	require.Nil(t, seedOfDatacenter(func() (map[string]*kubermaticv1.Seed, error) { return nil, errors.New("boom") }, "dc-a"))
}
