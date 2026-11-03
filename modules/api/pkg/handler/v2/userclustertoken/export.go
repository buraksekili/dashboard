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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-kit/kit/endpoint"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"

	apiv1 "k8c.io/dashboard/v2/pkg/api/v1"
	apiv2 "k8c.io/dashboard/v2/pkg/api/v2"
	handlerauth "k8c.io/dashboard/v2/pkg/handler/auth"
	"k8c.io/dashboard/v2/pkg/handler/middleware"
	handlercommon "k8c.io/dashboard/v2/pkg/handler/v1/common"
	"k8c.io/dashboard/v2/pkg/provider"
	authtypes "k8c.io/dashboard/v2/pkg/provider/auth/types"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	kubermaticv1helper "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1/helper"
	"k8c.io/kubermatic/v2/pkg/log"
	utilerrors "k8c.io/kubermatic/v2/pkg/util/errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// ExportPath is the path of the export flow below the /api/v2 prefix. The initial
	// request starts the OIDC login with the dashboard login client, and the identity
	// provider redirects back to the same path with the authorization code.
	ExportPath = "/clusters/{cluster_id}/kubeconfig/token"

	// ExportFullPath is ExportPath including the /api/v2 prefix.
	ExportFullPath = "/api/v2" + ExportPath

	// exportCookieName is the one-time cookie that carries the CSRF state, nonce and
	// PKCE verifier of an export across the OIDC login.
	exportCookieName = "kkp_kubeconfig_token_state"
	// exportCookieMaxAge is five minutes, enough for one login.
	exportCookieMaxAge = 300

	tokenIDLength    = 16
	secretRawLength  = 32 // 256 bits
	lifetimeQueryKey = "lifetime"
)

const (
	initialPhase = iota
	exchangeCodePhase
	kubeconfigGenerated
)

// exportState is marshalled into the OAuth state parameter. It carries the cluster ID
// and the requested lifetime through the identity provider redirect. It carries no
// user identity: the callback takes the identity only from the verified ID token.
type exportState struct {
	State     string `json:"state"`
	ClusterID string `json:"cluster_id"`
	// Lifetime is the requested token lifetime as a Go duration string. Empty means
	// the configured default.
	Lifetime string `json:"lifetime,omitempty"`
}

// ExportResponse is the one-time answer of a completed export.
// swagger:model KubeconfigTokenExport
type ExportResponse struct {
	// Token is the full token value. It is shown once and never stored by KKP.
	Token string `json:"token"`
	// TokenID is the ID of the token, safe to display and log.
	TokenID string `json:"tokenID"`
	// Kubeconfig is the ready-to-save kubeconfig file for the cluster.
	Kubeconfig string `json:"kubeconfig"`
	// ExpirationTime is when the token stops working.
	ExpirationTime apiv1.Time `json:"expirationTime"`
	// Settings are the lifetime rules that applied to this export.
	Settings apiv2.KubeconfigTokenSettings `json:"settings"`
}

// adminKubeconfigGetter is the part of provider.ClusterProvider that the export
// flow needs: reading the admin kubeconfig for the cluster endpoint and CA.
type adminKubeconfigGetter interface {
	GetAdminKubeconfigForUserCluster(ctx context.Context, cluster *kubermaticv1.Cluster) (*clientcmdapi.Config, error)
}

// ExportHandler serves the kubeconfig token export flow. It must only be installed
// when the UserClusterTokenWebhook feature gate is on and the dashboard login uses
// a client separate from the issuer client; otherwise the endpoint must not exist.
type ExportHandler struct {
	oidcLoginVerifier     authtypes.OIDCIssuerVerifier
	issuerClientID        string
	clusterProviderGetter provider.ClusterProviderGetter
	seedsGetter           provider.SeedsGetter
	seedClientGetter      provider.SeedClientGetter
	userProvider          provider.UserProvider
	memberMapper          provider.ProjectMemberMapper
	configGetter          provider.KubermaticConfigurationGetter
	masterClient          ctrlruntimeclient.Client
	rateLimiter           *userRateLimiter
}

// NewExportHandler creates the handler for the export flow.
func NewExportHandler(
	oidcLoginVerifier authtypes.OIDCIssuerVerifier,
	issuerClientID string,
	clusterProviderGetter provider.ClusterProviderGetter,
	seedsGetter provider.SeedsGetter,
	seedClientGetter provider.SeedClientGetter,
	userProvider provider.UserProvider,
	memberMapper provider.ProjectMemberMapper,
	configGetter provider.KubermaticConfigurationGetter,
	masterClient ctrlruntimeclient.Client,
	rateLimiter *userRateLimiter,
) *ExportHandler {
	return &ExportHandler{
		oidcLoginVerifier:     oidcLoginVerifier,
		issuerClientID:        issuerClientID,
		clusterProviderGetter: clusterProviderGetter,
		seedsGetter:           seedsGetter,
		seedClientGetter:      seedClientGetter,
		userProvider:          userProvider,
		memberMapper:          memberMapper,
		configGetter:          configGetter,
		masterClient:          masterClient,
		rateLimiter:           rateLimiter,
	}
}

// Install registers the export route on the given router.
func (h *ExportHandler) Install(router *mux.Router) {
	router.Methods(http.MethodGet).
		Path(ExportPath).
		Handler(h.exportEndpoint())
}

// swagger:route GET /api/v2/clusters/{cluster_id}/kubeconfig/token userclustertoken exportKubeconfigToken
//
//	Starts the OIDC login for exporting a kubeconfig token for the given cluster.
//	The identity provider redirects back to this path with an authorization code;
//	the response is then the one-time token and kubeconfig. This endpoint exists
//	only when per-cluster kubeconfig tokens are enabled and the dashboard login
//	uses its own OIDC client.
//
//	Produces:
//	- application/json
//	- text/html
//
//	Responses:
//	  default: errorResponse
//	  200: KubeconfigTokenExport
func (h *ExportHandler) exportEndpoint() http.Handler {
	return httptransport.NewServer(
		endpoint.Chain(
			middleware.SetClusterProvider(h.clusterProviderGetter, h.seedsGetter),
			middleware.SetPrivilegedClusterProvider(h.clusterProviderGetter, h.seedsGetter),
		)(h.export()),
		DecodeExportReq,
		EncodeExportResponse,
		httptransport.ServerErrorEncoder(handlerauth.OIDCCallbackErrorEncoder),
	)
}

func (h *ExportHandler) export() endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(exportReq)

		seed, cluster, err := h.findCluster(ctx, req.clusterID())
		if err != nil {
			return nil, err
		}

		settings := h.settings(ctx)

		kubeconfigGetter, ok := ctx.Value(middleware.ClusterProviderContextKey).(adminKubeconfigGetter)
		if !ok {
			return nil, utilerrors.New(http.StatusInternalServerError, "no cluster provider in request")
		}
		if req.phase == exchangeCodePhase {
			return h.exchangeCode(ctx, req, seed, kubeconfigGetter, cluster, settings)
		}
		if req.phase == initialPhase {
			return h.initialLogin(req, settings)
		}

		switch req.phase {
		}

		return nil, utilerrors.NewBadRequest("bad request unexpected phase %d, expected phase %d, did you forget to set the phase while decoding the request?", req.phase, initialPhase)
	}
}

// initialLogin starts the OIDC login with the dashboard login client.
func (h *ExportHandler) initialLogin(req exportReq, settings Settings) (interface{}, error) {
	oidcConfig := h.oidcLoginVerifier.OIDCConfig()

	oauthState := handlerauth.NewOAuthState()

	state := exportState{
		State:     oauthState.State,
		ClusterID: req.clusterID(),
		Lifetime:  req.Lifetime,
	}
	rawState, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}

	redirectURI, err := h.exportRedirectURI(req.clusterID())
	if err != nil {
		return nil, err
	}

	// no offline_access: the ID token is used once, during the callback
	scopes := []string{"openid", "email", "groups"}
	authCodeURL := h.oidcLoginVerifier.AuthCodeURL(
		url.QueryEscape(base64.StdEncoding.EncodeToString(rawState)),
		oidcConfig.OfflineAccessAsScope,
		redirectURI,
		oauthState.CodeVerifier,
		oauthState.Nonce,
		scopes...,
	)

	return exportRsp{
		phase:            initialPhase,
		authCodeURL:      authCodeURL,
		oauthState:       oauthState,
		secureCookieMode: oidcConfig.CookieSecureMode,
		secureCookie:     oidcConfig.SecureCookie,
	}, nil
}

// exportRedirectURI is this endpoint's own callback URL. Without it the OIDC client
// falls back to its default redirect URI (the legacy /api/v1/kubeconfig), which the
// login client does not have registered.
func (h *ExportHandler) exportRedirectURI(clusterID string) (string, error) {
	return h.oidcLoginVerifier.GetRedirectURI(strings.Replace("/api/v2"+ExportPath, "{cluster_id}", clusterID, 1))
}

// exchangeCode verifies the OIDC callback and issues the token.
func (h *ExportHandler) exchangeCode(
	ctx context.Context,
	req exportReq,
	seed *kubermaticv1.Seed,
	kubeconfigGetter adminKubeconfigGetter,
	cluster *kubermaticv1.Cluster,
	settings Settings,
) (interface{}, error) {
	oidcConfig := h.oidcLoginVerifier.OIDCConfig()

	if req.state.ClusterID != cluster.Name {
		return nil, utilerrors.NewBadRequest("state cluster ID does not match the requested cluster")
	}

	storedCookie, err := handlerauth.GetOAuthStateCookie(req.request, exportCookieName, oidcConfig.SecureCookie)
	if err != nil {
		return nil, err
	}
	if req.state.State != storedCookie.State {
		return nil, utilerrors.NewBadRequest("incorrect value of state parameter: %s", req.state.State)
	}

	redirectURI, err := h.exportRedirectURI(cluster.Name)
	if err != nil {
		return nil, err
	}

	tokens, err := h.oidcLoginVerifier.Exchange(ctx, req.code, redirectURI, storedCookie.CodeVerifier)
	if err != nil {
		return nil, utilerrors.NewBadRequest("error while exchanging oidc code for token: %v", err)
	}

	// identity comes only from the verified ID token
	claims, err := h.oidcLoginVerifier.Verify(ctx, tokens.IDToken)
	if err != nil {
		return nil, utilerrors.New(http.StatusUnauthorized, err.Error())
	}
	if claims.Nonce != storedCookie.Nonce {
		return nil, utilerrors.NewBadRequest("incorrect value of nonce claim in the ID token")
	}
	if claims.Email == "" {
		return nil, utilerrors.NewBadRequest("the token doesn't contain the mandatory \"email\" claim")
	}
	if !claims.EmailVerified {
		return nil, utilerrors.New(http.StatusForbidden, "the email address is not verified by the OIDC provider")
	}
	if slices.Contains(claims.Audience, h.issuerClientID) {
		return nil, utilerrors.New(http.StatusUnauthorized, "the ID token was issued for the user cluster client, not for the dashboard login client")
	}

	email := strings.ToLower(claims.Email)
	user, err := h.userProvider.UserByEmail(ctx, email)
	if err != nil {
		return nil, utilerrors.New(http.StatusForbidden, fmt.Sprintf("no KKP user for %q", email))
	}
	if user.DeletionTimestamp != nil {
		return nil, utilerrors.New(http.StatusForbidden, "the user is being deleted")
	}
	if user.Spec.Project != "" || kubermaticv1helper.IsProjectServiceAccount(user.Name) || kubermaticv1helper.IsProjectServiceAccount(email) {
		return nil, utilerrors.New(http.StatusForbidden, "project service accounts cannot hold kubeconfig tokens")
	}

	if !user.Spec.IsAdmin {
		projectID := cluster.Labels[kubermaticv1.ProjectIDLabelKey]
		roles, err := h.memberMapper.MapUserToRoles(ctx, user, projectID)
		if err != nil {
			return nil, handlercommon.KubernetesErrorToHTTPError(err)
		}
		if roles.Len() == 0 {
			return nil, utilerrors.New(http.StatusForbidden, fmt.Sprintf("you are not a member of the project that owns cluster %q", cluster.Name))
		}
	}

	if !h.rateLimiter.allow(user.Name, time.Now().UTC()) {
		return nil, utilerrors.New(http.StatusTooManyRequests, "too many kubeconfig token exports, try again later")
	}

	lifetime, err := requestedLifetime(req.state.Lifetime, settings)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if err := h.checkActiveCap(ctx, user.Name, cluster.Name, settings, now); err != nil {
		return nil, err
	}

	tokenID, err := newTokenID()
	if err != nil {
		return nil, err
	}
	secret, err := newTokenSecret()
	if err != nil {
		return nil, err
	}

	issuance := &kubermaticv1.UserClusterTokenIssuance{
		ObjectMeta: metav1ObjectName(tokenID, cluster.Name),
		Spec: kubermaticv1.UserClusterTokenSpec{
			TokenHash:         hashSecret(secret),
			UserID:            user.Name,
			ClusterID:         cluster.Name,
			ClusterUID:        string(cluster.UID),
			SeedName:          seed.Name,
			IssueTime:         metav1.Time{Time: now},
			ExpirationTime:    metav1.Time{Time: now.Add(lifetime)},
			Label:             "",
			IssuanceRequestID: req.state.State,
		},
	}
	if err := h.masterClient.Create(ctx, issuance); err != nil {
		return nil, handlercommon.KubernetesErrorToHTTPError(err)
	}

	// never log the token value or its hash
	log.Logger.Infow("issued kubeconfig token",
		"user", user.Name,
		"email", email,
		"cluster", cluster.Name,
		"seed", seed.Name,
		"tokenID", tokenID,
		"expires", issuance.Spec.ExpirationTime.Format(time.RFC3339))

	adminCfg, err := kubeconfigGetter.GetAdminKubeconfigForUserCluster(ctx, cluster)
	if err != nil {
		return nil, handlercommon.KubernetesErrorToHTTPError(err)
	}
	clusterEntry := adminClusterEntry(adminCfg, cluster.Name, cluster.Status.Address.APIServerExternalAddress)
	if clusterEntry == nil {
		return nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("unable to construct kubeconfig because couldn't find %s cluster entry in existing kubecfg", cluster.Name))
	}

	tokenValue := fmt.Sprintf("%s%s_%s:%s", kubermaticv1.UserClusterTokenPrefix, cluster.Name, tokenID, hex.EncodeToString(secret))
	kubeconfig := buildKubeconfig(cluster.Name, clusterEntry, email, tokenValue)

	kubeconfigYAML, err := clientcmd.Write(*kubeconfig)
	if err != nil {
		return nil, err
	}

	rsp := exportRsp{
		phase:            kubeconfigGenerated,
		tokenID:          tokenID,
		tokenValue:       tokenValue,
		kubeconfig:       string(kubeconfigYAML),
		expiration:       issuance.Spec.ExpirationTime.Time,
		settings:         settings,
		secureCookieMode: oidcConfig.CookieSecureMode,
		secureCookie:     oidcConfig.SecureCookie,
	}
	return rsp, nil
}

// checkActiveCap refuses the export when the user already holds the maximum number
// of unexpired tokens for the cluster. It never revokes an existing token.
func (h *ExportHandler) checkActiveCap(ctx context.Context, userID, clusterID string, settings Settings, now time.Time) error {
	issuances := &kubermaticv1.UserClusterTokenIssuanceList{}
	err := h.masterClient.List(ctx, issuances, ctrlruntimeclient.MatchingLabels{
		kubermaticv1.UserClusterTokenClusterIDLabel: clusterID,
	})
	if err != nil {
		return handlercommon.KubernetesErrorToHTTPError(err)
	}

	active := 0
	for _, issuance := range issuances.Items {
		if issuance.Spec.UserID == userID && issuance.Spec.ExpirationTime.After(now) {
			active++
		}
	}

	if active >= settings.MaxActivePerUserPerCluster {
		return utilerrors.New(http.StatusForbidden, fmt.Sprintf(
			"you already have %d active kubeconfig tokens for cluster %q, the maximum is %d; revoke one of them before exporting a new one",
			active, clusterID, settings.MaxActivePerUserPerCluster))
	}

	return nil
}

// findCluster returns the seed that hosts the cluster together with the Cluster
// object, read directly from the seed. The project is taken from the cluster's
// project label, never from the request.
func (h *ExportHandler) findCluster(ctx context.Context, clusterID string) (*kubermaticv1.Seed, *kubermaticv1.Cluster, error) {
	seeds, err := h.seedsGetter()
	if err != nil {
		return nil, nil, utilerrors.New(http.StatusInternalServerError, fmt.Sprintf("failed to list seeds: %v", err))
	}

	for _, seed := range seeds {
		if seed.Status.Phase == kubermaticv1.SeedInvalidPhase {
			continue
		}
		seedClient, err := h.seedClientGetter(seed)
		if err != nil {
			continue
		}
		cluster := &kubermaticv1.Cluster{}
		if err := seedClient.Get(ctx, types.NamespacedName{Name: clusterID}, cluster); err == nil {
			return seed, cluster, nil
		}
	}

	return nil, nil, utilerrors.New(http.StatusNotFound, fmt.Sprintf("cluster %q not found", clusterID))
}

func (h *ExportHandler) settings(ctx context.Context) Settings {
	if h.configGetter != nil {
		if cfg, err := h.configGetter(ctx); err == nil {
			return settingsFrom(cfg)
		}
	}
	return settingsFrom(nil)
}

// requestedLifetime resolves the lifetime of a new token. An empty request uses
// the configured default.
func requestedLifetime(requested string, settings Settings) (time.Duration, error) {
	if requested == "" {
		return settings.DefaultLifetime, nil
	}

	lifetime, err := time.ParseDuration(requested)
	if err != nil {
		return 0, utilerrors.NewBadRequest("invalid lifetime %q: %v", requested, err)
	}
	if lifetime < minLifetime {
		return 0, utilerrors.NewBadRequest("token lifetime must be at least %s, got %s", minLifetime, lifetime)
	}
	if lifetime > settings.MaxLifetime {
		return 0, utilerrors.NewBadRequest("token lifetime %s exceeds the maximum of %s", lifetime, settings.MaxLifetime)
	}

	return lifetime, nil
}

func newTokenID() (string, error) {
	raw := make([]byte, tokenIDLength/2) // hex encoding doubles the length
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("failed to generate a token ID: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func newTokenSecret() ([]byte, error) {
	raw := make([]byte, secretRawLength)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("failed to generate a token secret: %w", err)
	}
	return raw, nil
}

// metav1ObjectName returns the object meta of an issuance: the name is the token ID,
// the cluster label lets the API list a cluster's tokens. There is no user label:
// KKP User names are 64-character hashes, one more than a label value allows, so
// callers filter on spec.userID instead.
func metav1ObjectName(tokenID, clusterID string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name: tokenID,
		Labels: map[string]string{
			kubermaticv1.UserClusterTokenClusterIDLabel: clusterID,
		},
	}
}

// hashSecret returns the lowercase hex SHA-256 of the hex-encoded secret, the exact
// text that follows the colon in the token value.
func hashSecret(secret []byte) string {
	encoded := []byte(hex.EncodeToString(secret))
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// adminClusterEntry returns the clusterID entry of the admin kubeconfig, with the
// server replaced by the external address when one is set, or nil.
func adminClusterEntry(adminCfg *clientcmdapi.Config, clusterID, externalAddress string) *clientcmdapi.Cluster {
	entry, ok := adminCfg.Clusters[clusterID]
	if !ok || entry == nil {
		return nil
	}
	c := entry.DeepCopy()
	if externalAddress != "" {
		c.Server = externalAddress
	}
	return c
}

// buildKubeconfig returns a kubeconfig that carries only the cluster endpoint, its
// CA and the token: no exec block, no auth-provider, no identity provider data.
func buildKubeconfig(clusterID string, clusterEntry *clientcmdapi.Cluster, email, token string) *clientcmdapi.Config {
	cfg := clientcmdapi.NewConfig()

	clientCmdCluster := clientcmdapi.NewCluster()
	clientCmdCluster.Server = clusterEntry.Server
	clientCmdCluster.CertificateAuthorityData = clusterEntry.CertificateAuthorityData
	cfg.Clusters[clusterID] = clientCmdCluster

	authName := fmt.Sprintf("%s@%s", email, clusterID)
	clientCmdAuth := clientcmdapi.NewAuthInfo()
	clientCmdAuth.Token = token
	cfg.AuthInfos[authName] = clientCmdAuth

	clientCmdCtx := clientcmdapi.NewContext()
	clientCmdCtx.Cluster = clusterID
	clientCmdCtx.AuthInfo = authName
	cfg.Contexts[fmt.Sprintf("%s@%s", email, clusterID)] = clientCmdCtx
	cfg.CurrentContext = fmt.Sprintf("%s@%s", email, clusterID)

	return cfg
}

// exportReq is the decoded request of the export flow.
// swagger:parameters exportKubeconfigToken
type exportReq struct {
	// in: path
	ClusterID string `json:"cluster_id"`
	// in: query
	// +optional
	Lifetime string `json:"lifetime,omitempty"`

	request *http.Request
	phase   int

	// callback phase
	code     string
	rawState []byte
	state    exportState
}

// clusterID returns the cluster of the request in both phases.
func (r exportReq) clusterID() string {
	if r.phase == exchangeCodePhase {
		return r.state.ClusterID
	}
	return r.ClusterID
}

// GetSeedCluster lets the cluster provider middleware find the right seed.
func (r exportReq) GetSeedCluster() apiv1.SeedCluster {
	return apiv1.SeedCluster{
		ClusterID: r.clusterID(),
	}
}

// DecodeExportReq decodes both phases of the export flow.
func DecodeExportReq(_ context.Context, r *http.Request) (interface{}, error) {
	req := exportReq{request: r}

	{
		errType := r.URL.Query().Get("error")
		errMessage := r.URL.Query().Get("error_description")
		if len(errMessage) != 0 {
			return nil, fmt.Errorf("OIDC provider error %s: %s", errType, errMessage)
		}
	}

	code := r.URL.Query().Get("code")
	encodedState := r.URL.Query().Get("state")
	if code != "" || encodedState != "" {
		if code == "" || encodedState == "" {
			return nil, utilerrors.NewBadRequest("both code and state parameters are required")
		}

		unescapedState, err := url.QueryUnescape(encodedState)
		if err != nil {
			return nil, utilerrors.NewBadRequest("incorrect value of state parameter, expected url encoded value: %v", err)
		}
		rawState, err := base64.StdEncoding.DecodeString(unescapedState)
		if err != nil {
			return nil, utilerrors.NewBadRequest("incorrect value of state parameter, expected base64 encoded value: %v", err)
		}
		state := exportState{}
		if err := json.Unmarshal(rawState, &state); err != nil {
			return nil, utilerrors.NewBadRequest("incorrect value of state parameter, expected json encoded value: %v", err)
		}
		if _, err := r.Cookie(exportCookieName); err != nil {
			return nil, utilerrors.NewBadRequest("cookie %q not set: %v", exportCookieName, err)
		}

		req.phase = exchangeCodePhase
		req.code = code
		req.rawState = rawState
		req.state = state
		return req, nil
	}

	req.ClusterID = mux.Vars(r)["cluster_id"]
	if req.ClusterID == "" {
		return nil, utilerrors.NewBadRequest("cluster_id path parameter is required")
	}
	req.Lifetime = r.URL.Query().Get(lifetimeQueryKey)
	req.phase = initialPhase
	return req, nil
}

// exportRsp is the internal response of both phases.
type exportRsp struct {
	phase            int
	authCodeURL      string
	oauthState       handlerauth.OAuthState
	tokenID          string
	tokenValue       string
	kubeconfig       string
	expiration       time.Time
	settings         Settings
	secureCookieMode bool
	secureCookie     *securecookie.SecureCookie
}

// EncodeExportResponse writes the phase responses: a redirect to the identity
// provider for the initial phase, the one-time token for the callback.
func EncodeExportResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	rsp := response.(exportRsp)

	if rsp.phase == kubeconfigGenerated {
		handlerauth.ClearOAuthStateCookie(w, exportCookieName, "/", rsp.secureCookieMode)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		return json.NewEncoder(w).Encode(ExportResponse{
			Token:          rsp.tokenValue,
			TokenID:        rsp.tokenID,
			Kubeconfig:     rsp.kubeconfig,
			ExpirationTime: apiv1.NewTime(rsp.expiration),
			Settings:       rsp.settings.toAPI(),
		})
	}

	if err := handlerauth.SetOAuthStateCookie(w, exportCookieName, "/", rsp.oauthState, exportCookieMaxAge, rsp.secureCookieMode, rsp.secureCookie); err != nil {
		return fmt.Errorf("the cookie can't be created: %w", err)
	}

	w.Header().Add("Location", rsp.authCodeURL)
	w.Header().Add("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusSeeOther)
	return nil
}
