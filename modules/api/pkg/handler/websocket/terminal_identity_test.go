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

package websocket

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	authtypes "k8c.io/dashboard/v2/pkg/provider/auth/types"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func genTestSeed() *kubermaticv1.Seed {
	return &kubermaticv1.Seed{
		ObjectMeta: metav1.ObjectMeta{Name: "seed"},
		Spec: kubermaticv1.SeedSpec{
			Datacenters: map[string]kubermaticv1.Datacenter{"dc1": {}},
		},
	}
}

// setOIDC sets the deprecated spec.oidc, which the user cluster API server still honors.
func setOIDC(c *kubermaticv1.Cluster, settings kubermaticv1.OIDCSettings) {
	c.Spec.OIDC = settings //nolint:staticcheck
}

func oidcClaims(raw map[string]interface{}) authtypes.TokenClaims {
	claims := authtypes.TokenClaims{Subject: "sub", Raw: raw}
	if email, ok := raw["email"].(string); ok {
		claims.Email = email
	}
	return claims
}

func TestResolveWebTerminalIdentity(t *testing.T) {
	authConfigRef := &kubermaticv1.AuthenticationConfiguration{SecretName: "auth", SecretKey: "config.yaml"}

	testCases := []struct {
		name           string
		modifyCluster  func(*kubermaticv1.Cluster)
		modifySeed     func(*kubermaticv1.Seed)
		noSeed         bool
		claims         authtypes.TokenClaims
		expectedErr    error
		expectedUser   string
		expectedGroups []string
	}{
		{
			name:           "default mapping",
			claims:         oidcClaims(map[string]interface{}{"email": "Bob@Acme.com", "email_verified": true, "groups": []interface{}{"devs", "admins"}}),
			expectedUser:   "Bob@Acme.com",
			expectedGroups: []string{"oidc:admins", "oidc:devs", "system:authenticated"},
		},
		{
			name:           "default mapping without groups claim",
			claims:         oidcClaims(map[string]interface{}{"email": "bob@acme.com"}),
			expectedUser:   "bob@acme.com",
			expectedGroups: []string{"system:authenticated"},
		},
		{
			name:           "token without raw claims uses the parsed claims",
			claims:         authtypes.TokenClaims{Email: "bob@acme.com", Groups: []string{"devs"}},
			expectedUser:   "bob@acme.com",
			expectedGroups: []string{"oidc:devs", "system:authenticated"},
		},
		{
			name:        "unverified email",
			claims:      oidcClaims(map[string]interface{}{"email": "bob@acme.com", "email_verified": false}),
			expectedErr: errIdentityRejected,
		},
		{
			name:        "unverified email as string",
			claims:      oidcClaims(map[string]interface{}{"email": "bob@acme.com", "email_verified": "false"}),
			expectedErr: errIdentityRejected,
		},
		{
			name:        "system username",
			claims:      oidcClaims(map[string]interface{}{"email": "system:admin"}),
			expectedErr: errIdentityRejected,
		},
		{
			name: "spec.oidc mapping",
			modifyCluster: func(c *kubermaticv1.Cluster) {
				setOIDC(c, kubermaticv1.OIDCSettings{IssuerURL: "https://dex", ClientID: "kubernetes", UsernameClaim: "preferred_username", UsernamePrefix: "dex:", GroupsClaim: "roles", GroupsPrefix: "dex-"})
			},
			claims:         oidcClaims(map[string]interface{}{"email": "bob@acme.com", "preferred_username": "bob", "roles": "ops", "groups": []interface{}{"ignored"}}),
			expectedUser:   "dex:bob",
			expectedGroups: []string{"dex-ops", "system:authenticated"},
		},
		{
			name: "spec.oidc without groups claim",
			modifyCluster: func(c *kubermaticv1.Cluster) {
				setOIDC(c, kubermaticv1.OIDCSettings{IssuerURL: "https://dex", ClientID: "kubernetes", UsernameClaim: "email"})
			},
			claims:         oidcClaims(map[string]interface{}{"email": "bob@acme.com", "groups": []interface{}{"devs"}}),
			expectedUser:   "bob@acme.com",
			expectedGroups: []string{"system:authenticated"},
		},
		{
			name: "spec.oidc without username claim",
			modifyCluster: func(c *kubermaticv1.Cluster) {
				setOIDC(c, kubermaticv1.OIDCSettings{IssuerURL: "https://dex", ClientID: "kubernetes"})
			},
			claims:      oidcClaims(map[string]interface{}{"email": "bob@acme.com"}),
			expectedErr: errIdentityUnsupported,
		},
		{
			name: "spec.oidc username claim missing in the token",
			modifyCluster: func(c *kubermaticv1.Cluster) {
				setOIDC(c, kubermaticv1.OIDCSettings{IssuerURL: "https://dex", ClientID: "kubernetes", UsernameClaim: "preferred_username"})
			},
			claims:      oidcClaims(map[string]interface{}{"email": "bob@acme.com"}),
			expectedErr: errIdentityRejected,
		},
		{
			name: "spec.oidc mapping to a system group",
			modifyCluster: func(c *kubermaticv1.Cluster) {
				setOIDC(c, kubermaticv1.OIDCSettings{IssuerURL: "https://dex", ClientID: "kubernetes", UsernameClaim: "email", GroupsClaim: "groups"})
			},
			claims:      oidcClaims(map[string]interface{}{"email": "bob@acme.com", "groups": []interface{}{"system:masters"}}),
			expectedErr: errIdentityRejected,
		},
		{
			name: "spec.oidc mapping to a system username",
			modifyCluster: func(c *kubermaticv1.Cluster) {
				setOIDC(c, kubermaticv1.OIDCSettings{IssuerURL: "https://dex", ClientID: "kubernetes", UsernameClaim: "sub", UsernamePrefix: "system:"})
			},
			claims:      oidcClaims(map[string]interface{}{"email": "bob@acme.com", "sub": "bob"}),
			expectedErr: errIdentityRejected,
		},
		{
			name: "spec.oidc with only an issuer is ignored like KKP does",
			modifyCluster: func(c *kubermaticv1.Cluster) {
				setOIDC(c, kubermaticv1.OIDCSettings{IssuerURL: "https://dex", UsernameClaim: "sub"})
			},
			claims:         oidcClaims(map[string]interface{}{"email": "bob@acme.com"}),
			expectedUser:   "bob@acme.com",
			expectedGroups: []string{"system:authenticated"},
		},
		{
			name:          "cluster AuthenticationConfiguration",
			modifyCluster: func(c *kubermaticv1.Cluster) { c.Spec.AuthenticationConfiguration = authConfigRef },
			claims:        oidcClaims(map[string]interface{}{"email": "bob@acme.com"}),
			expectedErr:   errIdentityUnsupported,
		},
		{
			name: "datacenter AuthenticationConfiguration",
			modifySeed: func(s *kubermaticv1.Seed) {
				s.Spec.Datacenters["dc1"] = kubermaticv1.Datacenter{Spec: kubermaticv1.DatacenterSpec{AuthenticationConfiguration: authConfigRef}}
			},
			claims:      oidcClaims(map[string]interface{}{"email": "bob@acme.com"}),
			expectedErr: errIdentityUnsupported,
		},
		{
			name:        "seed AuthenticationConfiguration",
			modifySeed:  func(s *kubermaticv1.Seed) { s.Spec.AuthenticationConfiguration = authConfigRef },
			claims:      oidcClaims(map[string]interface{}{"email": "bob@acme.com"}),
			expectedErr: errIdentityUnsupported,
		},
		{
			name:        "unknown seed",
			noSeed:      true,
			claims:      oidcClaims(map[string]interface{}{"email": "bob@acme.com"}),
			expectedErr: errIdentityUnsupported,
		},
		{
			name:        "malformed groups claim",
			claims:      oidcClaims(map[string]interface{}{"email": "bob@acme.com", "groups": []interface{}{1}}),
			expectedErr: errIdentityRejected,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cluster := genTestCluster()
			if tc.modifyCluster != nil {
				tc.modifyCluster(cluster)
			}
			seed := genTestSeed()
			if tc.modifySeed != nil {
				tc.modifySeed(seed)
			}
			if tc.noSeed {
				seed = nil
			}

			identity, err := resolveWebTerminalIdentity(cluster, seed, tc.claims)
			if tc.expectedErr != nil {
				require.ErrorIs(t, err, tc.expectedErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expectedUser, identity.user)
			require.Equal(t, tc.expectedGroups, identity.groups)
		})
	}
}

func TestIdentityErrorStatus(t *testing.T) {
	require.Equal(t, WebTerminalIdentityRejected, identityErrorStatus(errIdentityRejected))
	require.Equal(t, WebTerminalIdentityUnsupported, identityErrorStatus(errIdentityUnsupported))
	require.Equal(t, WebTerminalIdentityUnsupported, identityErrorStatus(errors.New("other")))
}
