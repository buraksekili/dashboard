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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	authtypes "k8c.io/dashboard/v2/pkg/provider/auth/types"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	defaultUsernameClaim = "email"
	defaultGroupsClaim   = "groups"
	defaultGroupsPrefix  = "oidc:"
	systemPrefix         = "system:"
)

var (
	// errIdentityUnsupported means the user cluster maps OIDC claims in a way the web terminal cannot reproduce.
	errIdentityUnsupported = errors.New("the authentication configuration of the cluster is not supported by the web terminal")
	// errIdentityRejected means the token does not give an identity the web terminal may impersonate.
	errIdentityRejected = errors.New("the token does not give an identity the web terminal may impersonate")
)

// webTerminalIdentity is the user cluster identity the web terminal impersonates.
type webTerminalIdentity struct {
	user   string
	groups []string
}

// newWebTerminalIdentity returns an identity with the given username and already prefixed groups.
// The groups are deduplicated, sorted and always include system:authenticated.
func newWebTerminalIdentity(username string, groups []string) webTerminalIdentity {
	set := sets.New[string](user.AllAuthenticated)
	for _, g := range groups {
		if g != "" {
			set.Insert(g)
		}
	}
	return webTerminalIdentity{user: username, groups: sets.List(set)}
}

// hash returns a stable fingerprint of the identity, stored on the pod to detect identity changes.
func (i webTerminalIdentity) hash() string {
	groups := slices.Clone(i.groups)
	slices.Sort(groups)
	sum := sha256.Sum256([]byte(i.user + "\n" + strings.Join(groups, "\n")))
	return hex.EncodeToString(sum[:])
}

// claimMapping is the username and groups mapping of the user cluster JWT authenticator.
type claimMapping struct {
	usernameClaim  string
	usernamePrefix string
	groupsClaim    string
	groupsPrefix   string
}

// clusterClaimMapping returns how the user cluster API server maps OIDC claims to a user. It follows
// the precedence of the KKP AuthenticationConfiguration reconciler: a Secret referenced by the
// cluster, then by the datacenter or seed, then spec.oidc, then the KKP default. Only spec.oidc and
// the default can be reproduced here, an AuthenticationConfiguration Secret may use CEL expressions
// or several issuers.
func clusterClaimMapping(cluster *kubermaticv1.Cluster, seed *kubermaticv1.Seed) (claimMapping, error) {
	if cluster.Spec.AuthenticationConfiguration != nil {
		return claimMapping{}, fmt.Errorf("%w: the cluster references an AuthenticationConfiguration", errIdentityUnsupported)
	}
	if seed == nil {
		return claimMapping{}, fmt.Errorf("%w: the seed of the cluster is unknown", errIdentityUnsupported)
	}
	if dc, ok := seed.Spec.Datacenters[cluster.Spec.Cloud.DatacenterName]; ok && dc.Spec.AuthenticationConfiguration != nil {
		return claimMapping{}, fmt.Errorf("%w: the datacenter references an AuthenticationConfiguration", errIdentityUnsupported)
	}
	if seed.Spec.AuthenticationConfiguration != nil {
		return claimMapping{}, fmt.Errorf("%w: the seed references an AuthenticationConfiguration", errIdentityUnsupported)
	}

	//nolint:staticcheck // spec.oidc is deprecated, but still used by the user cluster API server
	oidc := cluster.Spec.OIDC
	if oidc.IssuerURL != "" && oidc.ClientID != "" {
		if oidc.UsernameClaim == "" {
			return claimMapping{}, fmt.Errorf("%w: spec.oidc has no username claim", errIdentityUnsupported)
		}
		return claimMapping{
			usernameClaim:  oidc.UsernameClaim,
			usernamePrefix: oidc.UsernamePrefix,
			groupsClaim:    oidc.GroupsClaim,
			groupsPrefix:   oidc.GroupsPrefix,
		}, nil
	}

	return claimMapping{
		usernameClaim: defaultUsernameClaim,
		groupsClaim:   defaultGroupsClaim,
		groupsPrefix:  defaultGroupsPrefix,
	}, nil
}

// resolveWebTerminalIdentity returns the identity the user cluster API server would give the token.
//
// Without spec.oidc this is the default KKP mapping: the email claim without a prefix and every
// groups claim entry with the "oidc:" prefix. Clusters with a custom AuthenticationConfiguration
// are refused, the claims could map to another user there.
func resolveWebTerminalIdentity(cluster *kubermaticv1.Cluster, seed *kubermaticv1.Seed, claims authtypes.TokenClaims) (webTerminalIdentity, error) {
	mapping, err := clusterClaimMapping(cluster, seed)
	if err != nil {
		return webTerminalIdentity{}, err
	}

	raw := claims.Raw
	if raw == nil {
		// not an OIDC ID token, only the parsed claims are known
		raw = map[string]interface{}{"email": claims.Email}
		if claims.Groups != nil {
			groups := make([]interface{}, 0, len(claims.Groups))
			for _, g := range claims.Groups {
				groups = append(groups, g)
			}
			raw["groups"] = groups
		}
	}

	if verified, ok := raw["email_verified"]; ok && !isTrue(verified) {
		return webTerminalIdentity{}, fmt.Errorf("%w: the email is not verified", errIdentityRejected)
	}

	username, ok := raw[mapping.usernameClaim].(string)
	if !ok || username == "" {
		return webTerminalIdentity{}, fmt.Errorf("%w: the token has no %q claim", errIdentityRejected, mapping.usernameClaim)
	}
	username = mapping.usernamePrefix + username
	if strings.HasPrefix(username, systemPrefix) {
		return webTerminalIdentity{}, fmt.Errorf("%w: the username %q is reserved", errIdentityRejected, username)
	}

	var groups []string
	if mapping.groupsClaim != "" {
		claimGroups, err := stringsClaim(raw[mapping.groupsClaim])
		if err != nil {
			return webTerminalIdentity{}, fmt.Errorf("%w: claim %q: %w", errIdentityRejected, mapping.groupsClaim, err)
		}
		for _, g := range claimGroups {
			if g == "" {
				continue
			}
			g = mapping.groupsPrefix + g
			// impersonating a system group like system:masters would bypass RBAC
			if strings.HasPrefix(g, systemPrefix) {
				return webTerminalIdentity{}, fmt.Errorf("%w: the group %q is reserved", errIdentityRejected, g)
			}
			groups = append(groups, g)
		}
	}

	return newWebTerminalIdentity(username, groups), nil
}

func isTrue(v interface{}) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(b, "true")
	default:
		return false
	}
}

// stringsClaim reads a claim that is either a string or a list of strings, like the API server does.
func stringsClaim(v interface{}) ([]string, error) {
	switch c := v.(type) {
	case nil:
		return nil, nil
	case string:
		return []string{c}, nil
	case []string:
		return c, nil
	case []interface{}:
		out := make([]string, 0, len(c))
		for _, item := range c {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("unexpected value of type %T", item)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unexpected value of type %T", v)
	}
}
