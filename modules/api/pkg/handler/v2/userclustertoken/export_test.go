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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"

	apiv1 "k8c.io/dashboard/v2/pkg/api/v1"
	handlerauth "k8c.io/dashboard/v2/pkg/handler/auth"
	"k8c.io/dashboard/v2/pkg/provider"
	authtypes "k8c.io/dashboard/v2/pkg/provider/auth/types"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlruntimefake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	testClusterID  = "abc123"
	testClusterUID = "uid-abc123"
	testProjectID  = "payments"
	testSeedName   = "europe-west3-c"
	testUserEmail  = "alice@example.com"
	// real KKP User names are 64-character SHA-256 hex strings; a shorter test
	// value hid that they do not fit in a label value.
	testUserID     = "ff8d9819fc0e12bf0d24892e45987e249a28dce836a85cad60e28eaaa8c6d976"
	issuerClientID = "kubermaticIssuer"
)

// fakeOIDCVerifier stands in for the dashboard login client in the export flow.
// Verify returns the configured claims; signature and audience checks are the
// real verifier's job and are tested in pkg/handler/auth.
type fakeOIDCVerifier struct {
	config *authtypes.OIDCConfiguration
	claims authtypes.TokenClaims

	// redirect URIs the handler passed, so tests can check they match the
	// URI registered at the identity provider
	authRedirectURI     string
	exchangeRedirectURI string
}

func (f *fakeOIDCVerifier) OIDCConfig() *authtypes.OIDCConfiguration { return f.config }

func (f *fakeOIDCVerifier) AuthCodeURL(_ string, _ bool, redirectURI string, _ string, _ string, _ ...string) string {
	f.authRedirectURI = redirectURI
	return "https://idp.example.com/auth"
}

func (f *fakeOIDCVerifier) Exchange(_ context.Context, _ string, redirectURI string, _ ...string) (authtypes.OIDCToken, error) {
	f.exchangeRedirectURI = redirectURI
	return authtypes.OIDCToken{IDToken: "fake-id-token"}, nil
}

func (f *fakeOIDCVerifier) RefreshAccessToken(context.Context, string) (authtypes.OIDCToken, error) {
	return authtypes.OIDCToken{}, nil
}

func (f *fakeOIDCVerifier) Verify(_ context.Context, _ string) (authtypes.TokenClaims, error) {
	return f.claims, nil
}

func (f *fakeOIDCVerifier) Extract(*http.Request) (string, error) { return "", nil }

func (f *fakeOIDCVerifier) GetRedirectURI(path string) (string, error) {
	return "https://kkp.example.com" + path, nil
}

// fakeUserProvider returns one fixed user.
type fakeUserProvider struct {
	user *kubermaticv1.User
}

func (p *fakeUserProvider) UserByEmail(_ context.Context, email string) (*kubermaticv1.User, error) {
	if p.user != nil && strings.EqualFold(p.user.Spec.Email, email) {
		return p.user, nil
	}
	return nil, provider.ErrNotFound
}

func (p *fakeUserProvider) CreateUser(_ context.Context, _, _ string, _ []string) (*kubermaticv1.User, error) {
	return p.user, nil
}

func (p *fakeUserProvider) UpdateUser(_ context.Context, user *kubermaticv1.User) (*kubermaticv1.User, error) {
	return user, nil
}

func (p *fakeUserProvider) UserByID(_ context.Context, id string) (*kubermaticv1.User, error) {
	if p.user != nil && p.user.Name == id {
		return p.user, nil
	}
	return nil, provider.ErrNotFound
}

func (p *fakeUserProvider) InvalidateToken(context.Context, *kubermaticv1.User, string, apiv1.Time) error {
	return nil
}

func (p *fakeUserProvider) GetInvalidatedTokens(context.Context, *kubermaticv1.User) ([]string, error) {
	return nil, nil
}

func (p *fakeUserProvider) List(context.Context) ([]kubermaticv1.User, error) {
	if p.user == nil {
		return nil, nil
	}
	return []kubermaticv1.User{*p.user}, nil
}

// fakeMemberMapper answers the membership question for one project.
type fakeMemberMapper struct {
	roles sets.Set[string]
	err   error
}

func (m *fakeMemberMapper) MapUserToGroup(context.Context, string, string) (string, error) {
	return "", nil
}

func (m *fakeMemberMapper) MappingsFor(context.Context, string) ([]*kubermaticv1.UserProjectBinding, error) {
	return nil, nil
}

func (m *fakeMemberMapper) GroupMappingsFor(context.Context, []string) ([]*kubermaticv1.GroupProjectBinding, error) {
	return nil, nil
}

func (m *fakeMemberMapper) MapUserToRoles(_ context.Context, _ *kubermaticv1.User, projectID string) (sets.Set[string], error) {
	if m.err != nil {
		return nil, m.err
	}
	if projectID == testProjectID {
		return m.roles, nil
	}
	return sets.New[string](), nil
}

func (m *fakeMemberMapper) MapUserToGroups(context.Context, *kubermaticv1.User, string) (sets.Set[string], error) {
	return sets.New[string](), nil
}

// fakeClusterProvider carries just enough of the provider interfaces for the
// export flow and the cluster provider middleware.
type fakeClusterProvider struct {
	provider.ClusterProvider
	provider.PrivilegedClusterProvider

	cluster    *kubermaticv1.Cluster
	adminCfg   *clientcmdapi.Config
	seedClient ctrlruntimeclient.Client
}

func (p *fakeClusterProvider) IsCluster(_ context.Context, clusterID string) bool {
	return clusterID == p.cluster.Name
}

func (p *fakeClusterProvider) Get(_ context.Context, _ *provider.UserInfo, clusterName string, _ *provider.ClusterGetOptions) (*kubermaticv1.Cluster, error) {
	if clusterName != p.cluster.Name {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "clusters"}, clusterName)
	}
	return p.cluster.DeepCopy(), nil
}

func (p *fakeClusterProvider) GetUnsecured(_ context.Context, _ *kubermaticv1.Project, clusterName string, _ *provider.ClusterGetOptions) (*kubermaticv1.Cluster, error) {
	if clusterName != p.cluster.Name {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "clusters"}, clusterName)
	}
	return p.cluster.DeepCopy(), nil
}

func (p *fakeClusterProvider) GetAdminKubeconfigForUserCluster(_ context.Context, _ *kubermaticv1.Cluster) (*clientcmdapi.Config, error) {
	return p.adminCfg, nil
}

func (p *fakeClusterProvider) GetSeedClusterAdminRuntimeClient() ctrlruntimeclient.Client {
	return p.seedClient
}

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	utilruntime.Must(kubermaticv1.AddToScheme(scheme))
	return scheme
}

func testCluster() *kubermaticv1.Cluster {
	return &kubermaticv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: testClusterID,
			UID:  types.UID(testClusterUID),
			Labels: map[string]string{
				kubermaticv1.ProjectIDLabelKey: testProjectID,
			},
		},
		Status: kubermaticv1.ClusterStatus{
			NamespaceName: "cluster-" + testClusterID,
		},
	}
}

func testUser() *kubermaticv1.User {
	return &kubermaticv1.User{
		ObjectMeta: metav1.ObjectMeta{Name: testUserID},
		Spec: kubermaticv1.UserSpec{
			Email:  testUserEmail,
			Groups: []string{"kkp-users"},
		},
	}
}

type exportFixture struct {
	handler   *ExportHandler
	router    *mux.Router
	master    ctrlruntimeclient.Client
	verifier  *fakeOIDCVerifier
	secCookie *securecookie.SecureCookie
}

func newExportFixture(t *testing.T, user *kubermaticv1.User, roles sets.Set[string], existingIssuances []ctrlruntimeclient.Object) *exportFixture {
	t.Helper()

	scheme := testScheme(t)
	cluster := testCluster()
	seed := &kubermaticv1.Seed{ObjectMeta: metav1.ObjectMeta{Name: testSeedName}}

	seedClient := ctrlruntimefake.NewClientBuilder().WithScheme(scheme).WithObjects(cluster).Build()
	master := ctrlruntimefake.NewClientBuilder().WithScheme(scheme).WithObjects(existingIssuances...).Build()

	clusterProvider := &fakeClusterProvider{
		cluster: cluster,
		adminCfg: &clientcmdapi.Config{
			Clusters: map[string]*clientcmdapi.Cluster{
				testClusterID: {
					Server:                   "https://" + testClusterID + ".kkp.example.com:6443",
					CertificateAuthorityData: []byte("test-ca"),
				},
			},
		},
		seedClient: seedClient,
	}

	secCookie := securecookie.New([]byte("0123456789abcdef0123456789abcdef"), nil)
	verifier := &fakeOIDCVerifier{
		config: &authtypes.OIDCConfiguration{
			URL:          "https://idp.example.com",
			ClientID:     "kubermatic-login",
			SecureCookie: secCookie,
		},
		claims: authtypes.TokenClaims{
			Email:         testUserEmail,
			EmailVerified: true,
			Nonce:         "nonce",
		},
	}

	h := &ExportHandler{
		oidcLoginVerifier: verifier,
		issuerClientID:    issuerClientID,
		clusterProviderGetter: func(_ *kubermaticv1.Seed) (provider.ClusterProvider, error) {
			return clusterProvider, nil
		},
		seedsGetter: func() (map[string]*kubermaticv1.Seed, error) {
			return map[string]*kubermaticv1.Seed{testSeedName: seed}, nil
		},
		seedClientGetter: func(_ *kubermaticv1.Seed) (ctrlruntimeclient.Client, error) {
			return seedClient, nil
		},
		userProvider: &fakeUserProvider{user: user},
		memberMapper: &fakeMemberMapper{roles: roles},
		masterClient: master,
		rateLimiter:  NewUserRateLimiter(),
	}

	router := mux.NewRouter()
	h.Install(router.PathPrefix("/api/v2").Subrouter())

	return &exportFixture{handler: h, router: router, master: master, verifier: verifier, secCookie: secCookie}
}

// startExport does the initial request and returns the state cookie it set.
func (f *exportFixture) startExport(t *testing.T, query string) *http.Cookie {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/v2/clusters/"+testClusterID+"/kubeconfig/token"+query, nil)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("initial request: got status %d, want %d, body: %s", rec.Code, http.StatusSeeOther, rec.Body.String())
	}

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == exportCookieName {
			return cookie
		}
	}
	t.Fatal("initial request did not set the state cookie")
	return nil
}

// finishExport does the callback request with a fresh state cookie that matches
// the verifier's nonce, and the requested lifetime.
func (f *exportFixture) finishExport(t *testing.T, lifetime string) (*httptest.ResponseRecorder, ExportResponse) {
	t.Helper()

	oauthState := handlerauth.NewOAuthState()
	f.verifier.claims.Nonce = oauthState.Nonce
	cookie := f.stateCookieWith(t, oauthState)

	state := exportState{State: oauthState.State, ClusterID: testClusterID, Lifetime: lifetime}
	rawState, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	encodedState := url.QueryEscape(base64.StdEncoding.EncodeToString(rawState))

	target := fmt.Sprintf("/api/v2/clusters/%s/kubeconfig/token?code=auth-code&state=%s", testClusterID, encodedState)
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.AddCookie(cookie)

	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)

	rsp := ExportResponse{}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &rsp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
	}

	return rec, rsp
}

// stateCookieWith builds a state cookie that matches the given export state.
func (f *exportFixture) stateCookieWith(t *testing.T, oauthState handlerauth.OAuthState) *http.Cookie {
	t.Helper()

	rec := httptest.NewRecorder()
	if err := handlerauth.SetOAuthStateCookie(rec, exportCookieName, "/", oauthState, exportCookieMaxAge, false, f.secCookie); err != nil {
		t.Fatal(err)
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == exportCookieName {
			return cookie
		}
	}
	t.Fatal("failed to build the state cookie")
	return nil
}

func listIssuances(t *testing.T, client ctrlruntimeclient.Client) []kubermaticv1.UserClusterTokenIssuance {
	t.Helper()

	list := &kubermaticv1.UserClusterTokenIssuanceList{}
	if err := client.List(context.Background(), list); err != nil {
		t.Fatal(err)
	}
	return list.Items
}

func TestExportInitialRequestRedirectsWithCookie(t *testing.T) {
	f := newExportFixture(t, testUser(), sets.New("editors"), nil)

	cookie := f.startExport(t, "")
	if cookie.MaxAge != exportCookieMaxAge {
		t.Errorf("state cookie max age = %d, want %d", cookie.MaxAge, exportCookieMaxAge)
	}
}

func TestExportUsesOwnRedirectURI(t *testing.T) {
	f := newExportFixture(t, testUser(), sets.New("editors"), nil)
	want := "https://kkp.example.com/api/v2/clusters/" + testClusterID + "/kubeconfig/token"

	f.startExport(t, "")
	if f.verifier.authRedirectURI != want {
		t.Errorf("authorize redirect_uri = %q, want %q", f.verifier.authRedirectURI, want)
	}

	rec, _ := f.finishExport(t, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("callback: got status %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if f.verifier.exchangeRedirectURI != want {
		t.Errorf("token exchange redirect_uri = %q, want %q (must equal the authorize one)", f.verifier.exchangeRedirectURI, want)
	}
}

func TestExportCallbackIssuesToken(t *testing.T) {
	f := newExportFixture(t, testUser(), sets.New("editors"), nil)
	rec, rsp := f.finishExport(t, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("callback: got status %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	prefix := kubermaticv1.UserClusterTokenPrefix + testClusterID + "_"
	if !strings.HasPrefix(rsp.Token, prefix) {
		t.Errorf("token %q does not start with %q", redact(rsp.Token), prefix)
	}
	parts := strings.SplitN(rsp.Token, ":", 2)
	if len(parts) != 2 || len(parts[1]) != 64 {
		t.Fatalf("token secret must be 64 hex characters, got %q", redact(rsp.Token))
	}
	tokenID := strings.TrimPrefix(parts[0], prefix)
	if len(tokenID) != tokenIDLength {
		t.Errorf("token ID %q must be %d characters", tokenID, tokenIDLength)
	}
	if rsp.TokenID != tokenID {
		t.Errorf("response token ID %q does not match the token value", rsp.TokenID)
	}

	issuances := listIssuances(t, f.master)
	if len(issuances) != 1 {
		t.Fatalf("got %d issuances, want 1", len(issuances))
	}
	issuance := issuances[0]
	if issuance.Name != tokenID {
		t.Errorf("issuance name %q, want the token ID %q", issuance.Name, tokenID)
	}
	if issuance.Spec.UserID != testUserID {
		t.Errorf("issuance userID = %q, want %q", issuance.Spec.UserID, testUserID)
	}
	if issuance.Spec.ClusterID != testClusterID {
		t.Errorf("issuance clusterID = %q, want %q", issuance.Spec.ClusterID, testClusterID)
	}
	if issuance.Spec.ClusterUID != testClusterUID {
		t.Errorf("issuance clusterUID = %q, want %q", issuance.Spec.ClusterUID, testClusterUID)
	}
	if issuance.Spec.SeedName != testSeedName {
		t.Errorf("issuance seedName = %q, want %q", issuance.Spec.SeedName, testSeedName)
	}
	if len(issuance.Spec.TokenHash) != 64 {
		t.Errorf("token hash must be 64 hex characters, got %q", issuance.Spec.TokenHash)
	}
	if _, ok := issuance.Labels[kubermaticv1.UserClusterTokenUserIDLabel]; ok {
		t.Errorf("issuance must not carry the user label (KKP User names exceed 63 characters): %v", issuance.Labels)
	}
	if issuance.Spec.UserID != testUserID {
		t.Errorf("issuance userID = %q, want %q", issuance.Spec.UserID, testUserID)
	}
	if issuance.Labels[kubermaticv1.UserClusterTokenClusterIDLabel] != testClusterID {
		t.Errorf("issuance cluster label missing: %v", issuance.Labels)
	}

	lifetime := issuance.Spec.ExpirationTime.Sub(issuance.Spec.IssueTime.Time)
	if lifetime != defaultLifetime {
		t.Errorf("token lifetime = %s, want the default %s", lifetime, defaultLifetime)
	}

	// the kubeconfig carries the cluster endpoint, its CA and the token, nothing else
	assertCleanKubeconfig(t, rsp.Kubeconfig, rsp.Token)
}

func TestExportCallbackHonorsRequestedLifetime(t *testing.T) {
	f := newExportFixture(t, testUser(), sets.New("editors"), nil)
	rec, _ := f.finishExport(t, "2h")
	if rec.Code != http.StatusOK {
		t.Fatalf("callback: got status %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	issuances := listIssuances(t, f.master)
	if len(issuances) != 1 {
		t.Fatalf("got %d issuances, want 1", len(issuances))
	}
	lifetime := issuances[0].Spec.ExpirationTime.Sub(issuances[0].Spec.IssueTime.Time)
	if lifetime != 2*time.Hour {
		t.Errorf("token lifetime = %s, want 2h", lifetime)
	}
}

func TestExportCallbackRejectsLifetimeAboveMax(t *testing.T) {
	f := newExportFixture(t, testUser(), sets.New("editors"), nil)
	rec, _ := f.finishExport(t, "200h")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("callback with lifetime above the maximum: got status %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if issuances := listIssuances(t, f.master); len(issuances) != 0 {
		t.Errorf("no issuance must be created, got %d", len(issuances))
	}
}

func TestExportCallbackRejectsIssuerAudience(t *testing.T) {
	f := newExportFixture(t, testUser(), sets.New("editors"), nil)
	f.verifier.claims.Audience = []string{"kubermatic-login", issuerClientID}
	rec, _ := f.finishExport(t, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("callback with an issuer-client token: got status %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if issuances := listIssuances(t, f.master); len(issuances) != 0 {
		t.Errorf("no issuance must be created, got %d", len(issuances))
	}
}

func TestExportCallbackRejectsUnverifiedEmail(t *testing.T) {
	f := newExportFixture(t, testUser(), sets.New("editors"), nil)
	f.verifier.claims.EmailVerified = false
	rec, _ := f.finishExport(t, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("callback with an unverified email: got status %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestExportCallbackRejectsNonceMismatch(t *testing.T) {
	f := newExportFixture(t, testUser(), sets.New("editors"), nil)
	// a state cookie whose nonce the verifier does not repeat
	oauthState := handlerauth.NewOAuthState()
	cookie := f.stateCookieWith(t, oauthState)
	f.verifier.claims.Nonce = "other-nonce"

	rawState, err := json.Marshal(exportState{State: oauthState.State, ClusterID: testClusterID})
	if err != nil {
		t.Fatal(err)
	}
	target := fmt.Sprintf("/api/v2/clusters/%s/kubeconfig/token?code=x&state=%s", testClusterID, url.QueryEscape(base64.StdEncoding.EncodeToString(rawState)))
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("callback with a wrong nonce: got status %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestExportCallbackRejectsServiceAccount(t *testing.T) {
	user := testUser()
	user.Name = "serviceaccount-7d4b5695vb"
	user.Spec.Email = "serviceaccount-7d4b5695vb@kubermatic"
	f := newExportFixture(t, user, sets.New("editors"), nil)
	f.verifier.claims.Email = user.Spec.Email

	rec, _ := f.finishExport(t, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("callback for a service account: got status %d, want %d", rec.Code, http.StatusForbidden)
	}
	if issuances := listIssuances(t, f.master); len(issuances) != 0 {
		t.Errorf("no issuance must be created, got %d", len(issuances))
	}
}

// A user who is a member of another project but not of the cluster's project
// must not get a token for this cluster (BOLA).
func TestExportCallbackRefusesForeignProjectMember(t *testing.T) {
	f := newExportFixture(t, testUser(), sets.New("editors"), nil)
	// the mapper answers for the cluster's project only; the fixture maps
	// testProjectID, so empty roles means "member elsewhere"
	f.handler.memberMapper = &fakeMemberMapper{roles: sets.New[string]()}

	rec, _ := f.finishExport(t, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("callback for a non-member: got status %d, want %d", rec.Code, http.StatusForbidden)
	}
	if issuances := listIssuances(t, f.master); len(issuances) != 0 {
		t.Errorf("no issuance must be created, got %d", len(issuances))
	}
}

func TestExportCallbackAdminNeedsNoMembership(t *testing.T) {
	user := testUser()
	user.Spec.IsAdmin = true
	f := newExportFixture(t, user, sets.New[string](), nil)

	rec, _ := f.finishExport(t, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("callback for an admin: got status %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func activeIssuance(id string) *kubermaticv1.UserClusterTokenIssuance {
	return &kubermaticv1.UserClusterTokenIssuance{
		ObjectMeta: metav1.ObjectMeta{
			Name: id,
			Labels: map[string]string{
				kubermaticv1.UserClusterTokenClusterIDLabel: testClusterID,
			},
		},
		Spec: kubermaticv1.UserClusterTokenSpec{
			TokenHash:      strings.Repeat("a", 64),
			UserID:         testUserID,
			ClusterID:      testClusterID,
			ClusterUID:     testClusterUID,
			SeedName:       testSeedName,
			IssueTime:      metav1.Time{Time: time.Now().Add(-time.Hour)},
			ExpirationTime: metav1.Time{Time: time.Now().Add(23 * time.Hour)},
		},
	}
}

// At the cap the export is refused with a clear message; existing tokens are
// never revoked silently.
func TestExportCallbackRefusesAtCap(t *testing.T) {
	existing := make([]ctrlruntimeclient.Object, 0, defaultMaxActivePerUserPerCluster)
	for i := range defaultMaxActivePerUserPerCluster {
		existing = append(existing, activeIssuance(fmt.Sprintf("tokenid%02dxxxxx", i)))
	}
	f := newExportFixture(t, testUser(), sets.New("editors"), existing)

	rec, _ := f.finishExport(t, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("callback at the cap: got status %d, want %d", rec.Code, http.StatusForbidden)
	}
	if !strings.Contains(rec.Body.String(), "revoke one of them") {
		t.Errorf("the refusal must tell the user to revoke a token, got: %s", rec.Body.String())
	}

	issuances := listIssuances(t, f.master)
	if len(issuances) != defaultMaxActivePerUserPerCluster {
		t.Errorf("existing tokens must stay, got %d issuances, want %d", len(issuances), defaultMaxActivePerUserPerCluster)
	}
}

// Another user's tokens on the same cluster do not count against the cap: with no
// user label, the cap filters the cluster's issuances by spec.userID.
func TestExportCallbackCapCountsOnlyOwnTokens(t *testing.T) {
	existing := make([]ctrlruntimeclient.Object, 0, defaultMaxActivePerUserPerCluster)
	for i := range defaultMaxActivePerUserPerCluster {
		other := activeIssuance(fmt.Sprintf("othertoken%02dxx", i))
		other.Spec.UserID = strings.Repeat("b", 64)
		existing = append(existing, other)
	}
	f := newExportFixture(t, testUser(), sets.New("editors"), existing)

	rec, _ := f.finishExport(t, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("callback with another user's tokens at the cap: got status %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// Expired tokens do not count against the cap.
func TestExportCallbackExpiredTokensDoNotCount(t *testing.T) {
	expired := activeIssuance("expiredtoken00")
	expired.Spec.ExpirationTime = metav1.Time{Time: time.Now().Add(-time.Minute)}
	f := newExportFixture(t, testUser(), sets.New("editors"), []ctrlruntimeclient.Object{expired})

	rec, _ := f.finishExport(t, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("callback with an expired token at the cap: got status %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestExportCallbackRateLimited(t *testing.T) {
	f := newExportFixture(t, testUser(), sets.New("editors"), nil)

	for range exportBurst {
		rec, _ := f.finishExport(t, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("export within the burst failed: status %d, body: %s", rec.Code, rec.Body.String())
		}
	}

	rec, _ := f.finishExport(t, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("export above the burst: got status %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
}

func TestExportCallbackUnknownCluster(t *testing.T) {
	f := newExportFixture(t, testUser(), sets.New("editors"), nil)

	state := exportState{State: "state", ClusterID: "othercl"}
	rawState, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	target := fmt.Sprintf("/api/v2/clusters/othercl/kubeconfig/token?code=x&state=%s", url.QueryEscape(base64.StdEncoding.EncodeToString(rawState)))
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.AddCookie(f.stateCookieWith(t, handlerauth.NewOAuthState()))

	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("callback for an unknown cluster: got status %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// assertCleanKubeconfig checks that the kubeconfig contains the cluster endpoint,
// the CA and the token, and no identity provider data.
func assertCleanKubeconfig(t *testing.T, kubeconfig, token string) {
	t.Helper()

	for _, want := range []string{
		"server: https://" + testClusterID + ".kkp.example.com:6443",
		"certificate-authority-data: " + base64.StdEncoding.EncodeToString([]byte("test-ca")),
		"token: " + token,
	} {
		if !strings.Contains(kubeconfig, want) {
			t.Errorf("kubeconfig does not contain %q:\n%s", want, kubeconfig)
		}
	}

	for _, forbidden := range []string{
		"idp-issuer-url",
		"client-id",
		"client-secret",
		"refresh-token",
		"id-token",
		"exec:",
		"auth-provider",
		"fake-id-token",
	} {
		if strings.Contains(kubeconfig, forbidden) {
			t.Errorf("kubeconfig must not contain %q:\n%s", forbidden, kubeconfig)
		}
	}
}

// redact hides the secret part of a token value in test failures.
func redact(token string) string {
	parts := strings.SplitN(token, ":", 2)
	if len(parts) == 2 {
		return parts[0] + ":<redacted>"
	}
	return "<redacted>"
}
