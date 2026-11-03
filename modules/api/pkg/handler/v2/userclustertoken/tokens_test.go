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
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	apiv2 "k8c.io/dashboard/v2/pkg/api/v2"
	"k8c.io/dashboard/v2/pkg/handler/middleware"
	"k8c.io/dashboard/v2/pkg/provider"

	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlruntimefake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const otherUserID = "0cea315e016cf37b5b1ce08426c66bc0051de5cd0e0df1997ab7ed36b091b3b6"

// fakeProjectProvider hands out one project; the secured Get refuses non-members.
type fakeProjectProvider struct {
	provider.ProjectProvider
	provider.PrivilegedProjectProvider

	project *kubermaticv1.Project
	member  bool
}

func (p *fakeProjectProvider) GetUnsecured(_ context.Context, _ string, _ *provider.ProjectGetOptions) (*kubermaticv1.Project, error) {
	return p.project, nil
}

func (p *fakeProjectProvider) Get(_ context.Context, _ *provider.UserInfo, _ string, _ *provider.ProjectGetOptions) (*kubermaticv1.Project, error) {
	if !p.member {
		return nil, apierrors.NewForbidden(schema.GroupResource{Group: "kubermatic.k8c.io", Resource: "projects"}, testProjectID, nil)
	}
	return p.project, nil
}

type tokenAPIFixture struct {
	api        *TokenAPI
	master     ctrlruntimeclient.Client
	seedClient ctrlruntimeclient.Client
	project    *fakeProjectProvider
	isAdmin    bool
}

func newTokenAPIFixture(t *testing.T, existingIssuances, seedTokens []ctrlruntimeclient.Object) *tokenAPIFixture {
	t.Helper()

	scheme := testScheme(t)
	seedClient := ctrlruntimefake.NewClientBuilder().WithScheme(scheme).WithObjects(seedTokens...).Build()
	master := ctrlruntimefake.NewClientBuilder().WithScheme(scheme).WithObjects(existingIssuances...).Build()

	f := &tokenAPIFixture{
		master:     master,
		seedClient: seedClient,
	}

	projectProvider := &fakeProjectProvider{
		project: &kubermaticv1.Project{ObjectMeta: metav1.ObjectMeta{Name: testProjectID}},
		member:  true,
	}

	f.api = &TokenAPI{
		userInfoGetter: func(_ context.Context, _ string) (*provider.UserInfo, error) {
			return &provider.UserInfo{Email: testUserEmail, IsAdmin: f.isAdmin}, nil
		},
		projectProvider:   projectProvider,
		privilegedProject: projectProvider,
		clusterProviderGetter: func(_ *kubermaticv1.Seed) (provider.ClusterProvider, error) {
			return &fakeClusterProvider{cluster: testCluster(), seedClient: seedClient}, nil
		},
		seedsGetter: func() (map[string]*kubermaticv1.Seed, error) {
			return map[string]*kubermaticv1.Seed{testSeedName: {ObjectMeta: metav1.ObjectMeta{Name: testSeedName}}}, nil
		},
		masterClient: master,
		userProvider: &fakeUserProvider{user: testUser()},
	}
	f.project = projectProvider

	return f
}

// requestContext builds a ctx like the middleware chain would: the authenticated
// user and the cluster providers.
func (f *tokenAPIFixture) requestContext() context.Context {
	user := testUser()
	ctx := context.WithValue(context.Background(), middleware.UserCRContextKey, user)
	clusterProvider := &fakeClusterProvider{cluster: testCluster(), seedClient: f.seedClient}
	ctx = context.WithValue(ctx, middleware.ClusterProviderContextKey, clusterProvider)
	ctx = context.WithValue(ctx, middleware.PrivilegedClusterProviderContextKey, clusterProvider)
	return ctx
}

func seedToken(id string, state kubermaticv1.UserClusterTokenState, lastUsed *metav1.Time) *kubermaticv1.UserClusterToken {
	return &kubermaticv1.UserClusterToken{
		ObjectMeta: metav1.ObjectMeta{Name: id, Namespace: "cluster-" + testClusterID},
		Status: kubermaticv1.UserClusterTokenStatus{
			State:        state,
			LastUsedTime: lastUsed,
		},
	}
}

func issuanceFor(userID, id, clusterID string) *kubermaticv1.UserClusterTokenIssuance {
	return &kubermaticv1.UserClusterTokenIssuance{
		ObjectMeta: metav1.ObjectMeta{
			Name: id,
			Labels: map[string]string{
				kubermaticv1.UserClusterTokenClusterIDLabel: clusterID,
			},
		},
		Spec: kubermaticv1.UserClusterTokenSpec{
			TokenHash:      strings.Repeat("a", 64),
			UserID:         userID,
			ClusterID:      clusterID,
			ClusterUID:     testClusterUID,
			SeedName:       testSeedName,
			IssueTime:      metav1.Time{Time: time.Now().Add(-time.Hour)},
			ExpirationTime: metav1.Time{Time: time.Now().Add(23 * time.Hour)},
			Label:          "old label",
		},
	}
}

func listTokens(t *testing.T, f *tokenAPIFixture) ([]apiv2.KubeconfigToken, error) {
	t.Helper()

	rsp, err := f.api.listEndpoint()(f.requestContext(), projectClusterReq{ProjectID: testProjectID, ClusterID: testClusterID})
	if err != nil {
		return nil, err
	}
	return rsp.([]apiv2.KubeconfigToken), nil
}

func TestListOwnTokens(t *testing.T) {
	lastUsed := metav1.Time{Time: time.Now().Add(-10 * time.Minute)}
	f := newTokenAPIFixture(t,
		[]ctrlruntimeclient.Object{
			issuanceFor(testUserID, "mytoken01", testClusterID),
			issuanceFor(testUserID, "mytoken02", testClusterID),
			issuanceFor(otherUserID, "bobtoken01", testClusterID), // other user, same cluster
			issuanceFor(testUserID, "othertoken", "othercluster"), // same user, other cluster
		},
		[]ctrlruntimeclient.Object{
			seedToken("mytoken01", kubermaticv1.UserClusterTokenActive, &lastUsed),
			seedToken("mytoken02", kubermaticv1.UserClusterTokenDisabled, nil),
		})

	tokens, err := listTokens(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 {
		t.Fatalf("got %d tokens, want 2 (only the user's own tokens for this cluster)", len(tokens))
	}

	byID := map[string]apiv2.KubeconfigToken{}
	for _, token := range tokens {
		byID[token.ID] = token
	}

	if byID["mytoken01"].State != string(kubermaticv1.UserClusterTokenActive) {
		t.Errorf("state of mytoken01 = %q, want Active", byID["mytoken01"].State)
	}
	if byID["mytoken01"].LastUsedTime == nil {
		t.Error("lastUsedTime of mytoken01 must come from the seed copy")
	}
	if byID["mytoken02"].State != string(kubermaticv1.UserClusterTokenDisabled) {
		t.Errorf("state of mytoken02 = %q, want Disabled", byID["mytoken02"].State)
	}

	// the response must never carry the hash
	encoded, err := json.Marshal(tokens)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "tokenHash") || strings.Contains(string(encoded), strings.Repeat("a", 64)) {
		t.Errorf("the token list must not contain the hash: %s", encoded)
	}
}

// A user who is not a member of the project gets no token list, even though the
// cluster exists (BOLA through the project ID).
func TestListTokensRefusesNonMember(t *testing.T) {
	f := newTokenAPIFixture(t, []ctrlruntimeclient.Object{issuanceFor(testUserID, "mytoken01", testClusterID)}, nil)
	f.project.member = false

	_, err := listTokens(t, f)
	if err == nil {
		t.Fatal("listing tokens of a foreign project must fail")
	}
	if !strings.Contains(err.Error(), "Forbidden") && !isHTTPStatus(err, 403) {
		t.Errorf("want a forbidden error, got: %v", err)
	}
}

func TestPatchTokenLabel(t *testing.T) {
	f := newTokenAPIFixture(t, []ctrlruntimeclient.Object{issuanceFor(testUserID, "mytoken01", testClusterID)}, nil)

	rsp, err := f.api.patchEndpoint()(f.requestContext(), tokenPatchReq{
		ProjectID: testProjectID,
		ClusterID: testClusterID,
		TokenID:   "mytoken01",
		Body:      apiv2.KubeconfigTokenPatch{Label: "laptop"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rsp.(apiv2.KubeconfigToken).Label != "laptop" {
		t.Errorf("label = %q, want laptop", rsp.(apiv2.KubeconfigToken).Label)
	}

	issuance := &kubermaticv1.UserClusterTokenIssuance{}
	if err := f.master.Get(context.Background(), types.NamespacedName{Name: "mytoken01"}, issuance); err != nil {
		t.Fatal(err)
	}
	if issuance.Spec.Label != "laptop" {
		t.Errorf("stored label = %q, want laptop", issuance.Spec.Label)
	}
}

func TestPatchTokenRejectsLongLabel(t *testing.T) {
	f := newTokenAPIFixture(t, []ctrlruntimeclient.Object{issuanceFor(testUserID, "mytoken01", testClusterID)}, nil)

	_, err := f.api.patchEndpoint()(f.requestContext(), tokenPatchReq{
		ProjectID: testProjectID,
		ClusterID: testClusterID,
		TokenID:   "mytoken01",
		Body:      apiv2.KubeconfigTokenPatch{Label: strings.Repeat("x", maxLabelLength+1)},
	})
	if !isHTTPStatus(err, 400) {
		t.Errorf("want a bad request for a too long label, got: %v", err)
	}
}

// Another user's token must not be patchable, and the error must not reveal it
// exists (BOLA).
func TestPatchOtherUsersTokenIsNotFound(t *testing.T) {
	f := newTokenAPIFixture(t, []ctrlruntimeclient.Object{issuanceFor(otherUserID, "bobtoken01", testClusterID)}, nil)

	_, err := f.api.patchEndpoint()(f.requestContext(), tokenPatchReq{
		ProjectID: testProjectID,
		ClusterID: testClusterID,
		TokenID:   "bobtoken01",
		Body:      apiv2.KubeconfigTokenPatch{Label: "nope"},
	})
	if !isHTTPStatus(err, 404) {
		t.Errorf("want not found for another user's token, got: %v", err)
	}

	issuance := &kubermaticv1.UserClusterTokenIssuance{}
	if err := f.master.Get(context.Background(), types.NamespacedName{Name: "bobtoken01"}, issuance); err != nil {
		t.Fatal(err)
	}
	if issuance.Spec.Label != "old label" {
		t.Errorf("the other user's label must be unchanged, got %q", issuance.Spec.Label)
	}
}

func TestRevokeTokenDeletesIssuance(t *testing.T) {
	f := newTokenAPIFixture(t, []ctrlruntimeclient.Object{issuanceFor(testUserID, "mytoken01", testClusterID)}, nil)

	_, err := f.api.revokeEndpoint()(f.requestContext(), tokenReq{ProjectID: testProjectID, ClusterID: testClusterID, TokenID: "mytoken01"})
	if err != nil {
		t.Fatal(err)
	}

	err = f.master.Get(context.Background(), types.NamespacedName{Name: "mytoken01"}, &kubermaticv1.UserClusterTokenIssuance{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("the issuance must be deleted, got: %v", err)
	}
}

func TestRevokeOtherUsersTokenIsNotFound(t *testing.T) {
	f := newTokenAPIFixture(t, []ctrlruntimeclient.Object{issuanceFor(otherUserID, "bobtoken01", testClusterID)}, nil)

	_, err := f.api.revokeEndpoint()(f.requestContext(), tokenReq{ProjectID: testProjectID, ClusterID: testClusterID, TokenID: "bobtoken01"})
	if !isHTTPStatus(err, 404) {
		t.Errorf("want not found for another user's token, got: %v", err)
	}

	err = f.master.Get(context.Background(), types.NamespacedName{Name: "bobtoken01"}, &kubermaticv1.UserClusterTokenIssuance{})
	if err != nil {
		t.Errorf("the other user's issuance must still exist, got: %v", err)
	}
}

func TestAdminListRequiresAdmin(t *testing.T) {
	f := newTokenAPIFixture(t, []ctrlruntimeclient.Object{issuanceFor(otherUserID, "bobtoken01", testClusterID)}, nil)
	f.isAdmin = false

	_, err := f.api.adminListEndpoint()(f.requestContext(), adminListReq{})
	if !isHTTPStatus(err, 403) {
		t.Errorf("want forbidden for a non-admin, got: %v", err)
	}
}

func TestAdminListFiltersAndResolvesEmail(t *testing.T) {
	f := newTokenAPIFixture(t, []ctrlruntimeclient.Object{
		issuanceFor(testUserID, "mytoken01", testClusterID),
		issuanceFor(otherUserID, "bobtoken01", testClusterID),
		issuanceFor(otherUserID, "bobtoken02", "othercluster"),
	}, nil)
	f.isAdmin = true

	rsp, err := f.api.adminListEndpoint()(f.requestContext(), adminListReq{ClusterID: testClusterID})
	if err != nil {
		t.Fatal(err)
	}
	tokens := rsp.([]apiv2.KubeconfigToken)
	if len(tokens) != 2 {
		t.Fatalf("got %d tokens for the cluster, want 2", len(tokens))
	}
	// the fixture only knows alice's user object, so only her token resolves an email
	byID := map[string]apiv2.KubeconfigToken{}
	for _, token := range tokens {
		byID[token.ID] = token
	}
	if byID["mytoken01"].UserEmail != testUserEmail {
		t.Errorf("user email of mytoken01 = %q, want %q", byID["mytoken01"].UserEmail, testUserEmail)
	}

	rsp, err = f.api.adminListEndpoint()(f.requestContext(), adminListReq{UserID: otherUserID})
	if err != nil {
		t.Fatal(err)
	}
	if len(rsp.([]apiv2.KubeconfigToken)) != 2 {
		t.Errorf("user filter: got %d tokens, want 2", len(rsp.([]apiv2.KubeconfigToken)))
	}
}

func TestAdminRevokeDeletesAnyToken(t *testing.T) {
	f := newTokenAPIFixture(t, []ctrlruntimeclient.Object{issuanceFor(otherUserID, "bobtoken01", testClusterID)}, nil)
	f.isAdmin = true

	_, err := f.api.adminRevokeEndpoint()(f.requestContext(), adminTokenReq{TokenID: "bobtoken01"})
	if err != nil {
		t.Fatal(err)
	}

	err = f.master.Get(context.Background(), types.NamespacedName{Name: "bobtoken01"}, &kubermaticv1.UserClusterTokenIssuance{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("the issuance must be deleted, got: %v", err)
	}
}

// isHTTPStatus checks the status of a utilerrors.HTTPError.
func isHTTPStatus(err error, code int) bool {
	var se interface{ StatusCode() int }
	if errors.As(err, &se) {
		return se.StatusCode() == code
	}
	return false
}
