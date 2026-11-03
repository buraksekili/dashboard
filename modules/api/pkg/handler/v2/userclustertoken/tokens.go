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
	"net/http"

	"github.com/go-kit/kit/endpoint"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"

	apiv1 "k8c.io/dashboard/v2/pkg/api/v1"
	apiv2 "k8c.io/dashboard/v2/pkg/api/v2"
	"k8c.io/dashboard/v2/pkg/handler"
	kubeconfigcommon "k8c.io/dashboard/v2/pkg/handler/common"
	"k8c.io/dashboard/v2/pkg/handler/middleware"
	"k8c.io/dashboard/v2/pkg/handler/v1/common"
	"k8c.io/dashboard/v2/pkg/provider"
	authtypes "k8c.io/dashboard/v2/pkg/provider/auth/types"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	utilerrors "k8c.io/kubermatic/v2/pkg/util/errors"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// maxLabelLength mirrors the CRD limit on spec.label.
const maxLabelLength = 128

// seedRuntimeClientGetter is the part of provider.PrivilegedClusterProvider the
// token list needs: a client for the seed that hosts the cluster.
type seedRuntimeClientGetter interface {
	GetSeedClusterAdminRuntimeClient() ctrlruntimeclient.Client
}

// TokenAPI serves the kubeconfig token management endpoints. Like the export
// handler it must only be installed when per-cluster kubeconfig tokens are enabled.
type TokenAPI struct {
	serverOpts        []httptransport.ServerOption
	tokenVerifiers    authtypes.TokenVerifier
	userProvider      provider.UserProvider
	userInfoGetter    provider.UserInfoGetter
	projectProvider   provider.ProjectProvider
	privilegedProject provider.PrivilegedProjectProvider

	clusterProviderGetter provider.ClusterProviderGetter
	seedsGetter           provider.SeedsGetter
	configGetter          provider.KubermaticConfigurationGetter
	masterClient          ctrlruntimeclient.Client
}

// NewTokenAPI creates the handler for the token management endpoints.
func NewTokenAPI(
	tokenVerifiers authtypes.TokenVerifier,
	userProvider provider.UserProvider,
	userInfoGetter provider.UserInfoGetter,
	projectProvider provider.ProjectProvider,
	privilegedProject provider.PrivilegedProjectProvider,
	clusterProviderGetter provider.ClusterProviderGetter,
	seedsGetter provider.SeedsGetter,
	configGetter provider.KubermaticConfigurationGetter,
	masterClient ctrlruntimeclient.Client,
	serverOptions ...httptransport.ServerOption,
) *TokenAPI {
	return &TokenAPI{
		serverOpts:            serverOptions,
		tokenVerifiers:        tokenVerifiers,
		userProvider:          userProvider,
		userInfoGetter:        userInfoGetter,
		projectProvider:       projectProvider,
		privilegedProject:     privilegedProject,
		clusterProviderGetter: clusterProviderGetter,
		seedsGetter:           seedsGetter,
		configGetter:          configGetter,
		masterClient:          masterClient,
	}
}

// Install registers the token management routes.
func (a *TokenAPI) Install(router *mux.Router) {
	router.Methods(http.MethodGet).
		Path("/projects/{project_id}/clusters/{cluster_id}/kubeconfig/tokens").
		Handler(a.list())

	router.Methods(http.MethodGet).
		Path("/projects/{project_id}/clusters/{cluster_id}/kubeconfig/tokens/settings").
		Handler(a.getSettings())

	router.Methods(http.MethodPatch).
		Path("/projects/{project_id}/clusters/{cluster_id}/kubeconfig/tokens/{token_id}").
		Handler(a.patch())

	router.Methods(http.MethodDelete).
		Path("/projects/{project_id}/clusters/{cluster_id}/kubeconfig/tokens/{token_id}").
		Handler(a.revoke())

	router.Methods(http.MethodGet).
		Path("/admin/kubeconfig/tokens").
		Handler(a.adminList())

	router.Methods(http.MethodDelete).
		Path("/admin/kubeconfig/tokens/{token_id}").
		Handler(a.adminRevoke())
}

// swagger:route GET /api/v2/projects/{project_id}/clusters/{cluster_id}/kubeconfig/tokens userclustertoken listKubeconfigTokens
//
//	Lists the kubeconfig tokens of the authenticated user for the given cluster.
//	The response never contains a token secret or its hash.
//
//	Produces:
//	- application/json
//
//	Responses:
//	  default: errorResponse
//	  200: []KubeconfigToken
//	  401: empty
//	  403: empty
func (a *TokenAPI) list() http.Handler {
	return httptransport.NewServer(
		endpoint.Chain(
			middleware.TokenVerifier(a.tokenVerifiers, a.userProvider),
			middleware.UserSaver(a.userProvider),
			middleware.SetClusterProvider(a.clusterProviderGetter, a.seedsGetter),
			middleware.SetPrivilegedClusterProvider(a.clusterProviderGetter, a.seedsGetter),
		)(a.listEndpoint()),
		decodeProjectClusterReq,
		handler.EncodeJSON,
		a.serverOptions()...,
	)
}

// swagger:route GET /api/v2/projects/{project_id}/clusters/{cluster_id}/kubeconfig/tokens/settings userclustertoken getKubeconfigTokenSettings
//
//	Returns the lifetime rules for new kubeconfig tokens of the given cluster.
//
//	Produces:
//	- application/json
//
//	Responses:
//	  default: errorResponse
//	  200: KubeconfigTokenSettings
//	  401: empty
//	  403: empty
func (a *TokenAPI) getSettings() http.Handler {
	return httptransport.NewServer(
		endpoint.Chain(
			middleware.TokenVerifier(a.tokenVerifiers, a.userProvider),
			middleware.UserSaver(a.userProvider),
			middleware.SetClusterProvider(a.clusterProviderGetter, a.seedsGetter),
			middleware.SetPrivilegedClusterProvider(a.clusterProviderGetter, a.seedsGetter),
		)(a.settingsEndpoint()),
		decodeProjectClusterReq,
		handler.EncodeJSON,
		a.serverOptions()...,
	)
}

// swagger:route PATCH /api/v2/projects/{project_id}/clusters/{cluster_id}/kubeconfig/tokens/{token_id} userclustertoken patchKubeconfigToken
//
//	Updates the label of one of the authenticated user's kubeconfig tokens for the
//	given cluster.
//
//	Consumes:
//	- application/json
//
//	Produces:
//	- application/json
//
//	Responses:
//	  default: errorResponse
//	  200: KubeconfigToken
//	  401: empty
//	  403: empty
func (a *TokenAPI) patch() http.Handler {
	return httptransport.NewServer(
		endpoint.Chain(
			middleware.TokenVerifier(a.tokenVerifiers, a.userProvider),
			middleware.UserSaver(a.userProvider),
			middleware.SetClusterProvider(a.clusterProviderGetter, a.seedsGetter),
			middleware.SetPrivilegedClusterProvider(a.clusterProviderGetter, a.seedsGetter),
		)(a.patchEndpoint()),
		decodeTokenPatchReq,
		handler.EncodeJSON,
		a.serverOptions()...,
	)
}

// swagger:route DELETE /api/v2/projects/{project_id}/clusters/{cluster_id}/kubeconfig/tokens/{token_id} userclustertoken revokeKubeconfigToken
//
//	Revokes one of the authenticated user's kubeconfig tokens for the given cluster.
//	The cluster rejects the token within the webhook cache TTL afterwards.
//
//	Produces:
//	- application/json
//
//	Responses:
//	  default: errorResponse
//	  200: empty
//	  401: empty
//	  403: empty
func (a *TokenAPI) revoke() http.Handler {
	return httptransport.NewServer(
		endpoint.Chain(
			middleware.TokenVerifier(a.tokenVerifiers, a.userProvider),
			middleware.UserSaver(a.userProvider),
			middleware.SetClusterProvider(a.clusterProviderGetter, a.seedsGetter),
			middleware.SetPrivilegedClusterProvider(a.clusterProviderGetter, a.seedsGetter),
		)(a.revokeEndpoint()),
		decodeTokenReq,
		handler.EncodeJSON,
		a.serverOptions()...,
	)
}

// swagger:route GET /api/v2/admin/kubeconfig/tokens admin listAllKubeconfigTokens
//
//	Lists kubeconfig tokens of all users, optionally filtered by cluster or user.
//	Admin only.
//
//	Produces:
//	- application/json
//
//	Responses:
//	  default: errorResponse
//	  200: []KubeconfigToken
//	  401: empty
//	  403: empty
func (a *TokenAPI) adminList() http.Handler {
	return httptransport.NewServer(
		endpoint.Chain(
			middleware.TokenVerifier(a.tokenVerifiers, a.userProvider),
			middleware.UserSaver(a.userProvider),
		)(a.adminListEndpoint()),
		decodeAdminListReq,
		handler.EncodeJSON,
		a.serverOptions()...,
	)
}

// swagger:route DELETE /api/v2/admin/kubeconfig/tokens/{token_id} admin revokeAnyKubeconfigToken
//
//	Revokes any kubeconfig token by its ID. Admin only.
//
//	Produces:
//	- application/json
//
//	Responses:
//	  default: errorResponse
//	  200: empty
//	  401: empty
//	  403: empty
func (a *TokenAPI) adminRevoke() http.Handler {
	return httptransport.NewServer(
		endpoint.Chain(
			middleware.TokenVerifier(a.tokenVerifiers, a.userProvider),
			middleware.UserSaver(a.userProvider),
		)(a.adminRevokeEndpoint()),
		decodeAdminTokenReq,
		handler.EncodeJSON,
		a.serverOptions()...,
	)
}

// serverOptions are the per-route options plus the shared ones from the caller. The
// caller must pass the token extractor: without it TokenVerifier finds no token and
// every request fails with "not authorized".
func (a *TokenAPI) serverOptions() []httptransport.ServerOption {
	return append([]httptransport.ServerOption{
		httptransport.ServerBefore(middleware.SetSeedsGetter(a.seedsGetter)),
	}, a.serverOpts...)
}

func (a *TokenAPI) listEndpoint() endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(projectClusterReq)
		user := authenticatedUser(ctx)

		project, err := common.GetProject(ctx, a.userInfoGetter, a.projectProvider, a.privilegedProject, req.ProjectID, nil)
		if err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}
		cluster, err := kubeconfigcommon.GetCluster(ctx, a.projectProvider, a.privilegedProject, a.userInfoGetter, project.Name, req.ClusterID, nil)
		if err != nil {
			return nil, err
		}

		issuances := &kubermaticv1.UserClusterTokenIssuanceList{}
		if err := a.masterClient.List(ctx, issuances, ctrlruntimeclient.MatchingLabels{
			kubermaticv1.UserClusterTokenClusterIDLabel: cluster.Name,
		}); err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}

		seedStates := a.seedTokenStates(ctx, cluster)

		tokens := []apiv2.KubeconfigToken{}
		for _, issuance := range issuances.Items {
			if issuance.Spec.UserID != user.Name {
				continue
			}
			token := issuanceToAPI(issuance)
			if state, ok := seedStates[issuance.Name]; ok {
				token.State = string(state.State)
				token.Reason = string(state.Reason)
				if state.LastUsedTime != nil {
					lastUsed := apiv1.NewTime(state.LastUsedTime.Time)
					token.LastUsedTime = &lastUsed
				}
			}
			tokens = append(tokens, token)
		}

		return tokens, nil
	}
}

func (a *TokenAPI) settingsEndpoint() endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(projectClusterReq)

		if _, err := common.GetProject(ctx, a.userInfoGetter, a.projectProvider, a.privilegedProject, req.ProjectID, nil); err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}

		var cfg *kubermaticv1.KubermaticConfiguration
		if a.configGetter != nil {
			// a broken getter falls back to the defaults, like the export flow
			if c, err := a.configGetter(ctx); err == nil {
				cfg = c
			}
		}

		return settingsFrom(cfg).toAPI(), nil
	}
}

func (a *TokenAPI) patchEndpoint() endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(tokenPatchReq)
		user := authenticatedUser(ctx)

		if len(req.Body.Label) > maxLabelLength {
			return nil, utilerrors.NewBadRequest("the token label must be at most %d characters", maxLabelLength)
		}

		project, err := common.GetProject(ctx, a.userInfoGetter, a.projectProvider, a.privilegedProject, req.ProjectID, nil)
		if err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}
		cluster, err := kubeconfigcommon.GetCluster(ctx, a.projectProvider, a.privilegedProject, a.userInfoGetter, project.Name, req.ClusterID, nil)
		if err != nil {
			return nil, err
		}

		issuance, err := a.getOwnIssuance(ctx, user.Name, cluster.Name, req.TokenID)
		if err != nil {
			return nil, err
		}

		issuance.Spec.Label = req.Body.Label
		if err := a.masterClient.Update(ctx, issuance); err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}

		return issuanceToAPI(*issuance), nil
	}
}

func (a *TokenAPI) revokeEndpoint() endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(tokenReq)
		user := authenticatedUser(ctx)

		project, err := common.GetProject(ctx, a.userInfoGetter, a.projectProvider, a.privilegedProject, req.ProjectID, nil)
		if err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}
		cluster, err := kubeconfigcommon.GetCluster(ctx, a.projectProvider, a.privilegedProject, a.userInfoGetter, project.Name, req.ClusterID, nil)
		if err != nil {
			return nil, err
		}

		issuance, err := a.getOwnIssuance(ctx, user.Name, cluster.Name, req.TokenID)
		if err != nil {
			return nil, err
		}

		if err := a.masterClient.Delete(ctx, issuance); err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}

		return nil, nil
	}
}

func (a *TokenAPI) adminListEndpoint() endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(adminListReq)

		adminInfo, err := a.userInfoGetter(ctx, "")
		if err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}
		if !adminInfo.IsAdmin {
			return nil, utilerrors.New(http.StatusForbidden, "only KKP admins may list all kubeconfig tokens")
		}

		selector := labels.NewSelector()
		if req.ClusterID != "" {
			// filtering happens after the list; the cluster ID is a label but the
			// user ID needs a lookup anyway, so filter in memory
			_ = selector
		}

		issuances := &kubermaticv1.UserClusterTokenIssuanceList{}
		if err := a.masterClient.List(ctx, issuances); err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}

		userEmails := map[string]string{}
		users, err := a.userProvider.List(ctx)
		if err == nil {
			for _, user := range users {
				userEmails[user.Name] = user.Spec.Email
			}
		}

		tokens := []apiv2.KubeconfigToken{}
		for _, issuance := range issuances.Items {
			if req.ClusterID != "" && issuance.Spec.ClusterID != req.ClusterID {
				continue
			}
			if req.UserID != "" && issuance.Spec.UserID != req.UserID {
				continue
			}
			token := issuanceToAPI(issuance)
			token.UserEmail = userEmails[issuance.Spec.UserID]
			tokens = append(tokens, token)
		}

		return tokens, nil
	}
}

func (a *TokenAPI) adminRevokeEndpoint() endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(adminTokenReq)

		adminInfo, err := a.userInfoGetter(ctx, "")
		if err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}
		if !adminInfo.IsAdmin {
			return nil, utilerrors.New(http.StatusForbidden, "only KKP admins may revoke kubeconfig tokens of other users")
		}

		issuance := &kubermaticv1.UserClusterTokenIssuance{}
		if err := a.masterClient.Get(ctx, types.NamespacedName{Name: req.TokenID}, issuance); err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}

		if err := a.masterClient.Delete(ctx, issuance); err != nil {
			return nil, common.KubernetesErrorToHTTPError(err)
		}

		return nil, nil
	}
}

// getOwnIssuance returns the issuance only when it belongs to the user and the
// cluster; anything else is a not found, so the API does not reveal other users'
// token IDs.
func (a *TokenAPI) getOwnIssuance(ctx context.Context, userID, clusterID, tokenID string) (*kubermaticv1.UserClusterTokenIssuance, error) {
	issuance := &kubermaticv1.UserClusterTokenIssuance{}
	if err := a.masterClient.Get(ctx, types.NamespacedName{Name: tokenID}, issuance); err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	if issuance.Spec.UserID != userID || issuance.Spec.ClusterID != clusterID {
		return nil, utilerrors.NewNotFound("userclustertokenissuance", tokenID)
	}
	return issuance, nil
}

// seedTokenStates reads the seed copies of the cluster's tokens, which carry the
// state and last-used time written on the seed.
func (a *TokenAPI) seedTokenStates(ctx context.Context, cluster *kubermaticv1.Cluster) map[string]kubermaticv1.UserClusterTokenStatus {
	states := map[string]kubermaticv1.UserClusterTokenStatus{}

	seedClient, ok := ctx.Value(middleware.PrivilegedClusterProviderContextKey).(seedRuntimeClientGetter)
	if !ok || cluster.Status.NamespaceName == "" {
		return states
	}

	tokens := &kubermaticv1.UserClusterTokenList{}
	if err := seedClient.GetSeedClusterAdminRuntimeClient().List(ctx, tokens, ctrlruntimeclient.InNamespace(cluster.Status.NamespaceName)); err != nil {
		// the seed states are informational; listing must work without them
		return states
	}
	for _, token := range tokens.Items {
		states[token.Name] = token.Status
	}

	return states
}

func issuanceToAPI(issuance kubermaticv1.UserClusterTokenIssuance) apiv2.KubeconfigToken {
	return apiv2.KubeconfigToken{
		ID:             issuance.Name,
		ClusterID:      issuance.Spec.ClusterID,
		UserID:         issuance.Spec.UserID,
		Label:          issuance.Spec.Label,
		IssueTime:      apiv1.NewTime(issuance.Spec.IssueTime.Time),
		ExpirationTime: apiv1.NewTime(issuance.Spec.ExpirationTime.Time),
	}
}

// authenticatedUser returns the KKP User the token verifier middleware put in the ctx.
func authenticatedUser(ctx context.Context) *kubermaticv1.User {
	return ctx.Value(middleware.UserCRContextKey).(*kubermaticv1.User)
}

// projectClusterReq identifies a cluster of a project.
// swagger:parameters listKubeconfigTokens getKubeconfigTokenSettings
type projectClusterReq struct {
	// in: path
	ProjectID string `json:"project_id"`
	// in: path
	ClusterID string `json:"cluster_id"`
}

// GetProjectID implements ProjectGetter.
func (r projectClusterReq) GetProjectID() string {
	return r.ProjectID
}

// GetSeedCluster lets the cluster provider middleware find the right seed.
func (r projectClusterReq) GetSeedCluster() apiv1.SeedCluster {
	return apiv1.SeedCluster{ClusterID: r.ClusterID}
}

// tokenReq identifies one token of a cluster of a project.
// swagger:parameters revokeKubeconfigToken
type tokenReq struct {
	// in: path
	ProjectID string `json:"project_id"`
	// in: path
	ClusterID string `json:"cluster_id"`
	// in: path
	TokenID string `json:"token_id"`
}

// GetProjectID implements ProjectGetter.
func (r tokenReq) GetProjectID() string {
	return r.ProjectID
}

// GetSeedCluster lets the cluster provider middleware find the right seed.
func (r tokenReq) GetSeedCluster() apiv1.SeedCluster {
	return apiv1.SeedCluster{ClusterID: r.ClusterID}
}

// tokenPatchReq updates the label of one token.
// swagger:parameters patchKubeconfigToken
type tokenPatchReq struct {
	// in: path
	ProjectID string `json:"project_id"`
	// in: path
	ClusterID string `json:"cluster_id"`
	// in: path
	TokenID string `json:"token_id"`

	// in: body
	Body apiv2.KubeconfigTokenPatch `json:"body"`
}

// GetProjectID implements ProjectGetter.
func (r tokenPatchReq) GetProjectID() string {
	return r.ProjectID
}

// GetSeedCluster lets the cluster provider middleware find the right seed.
func (r tokenPatchReq) GetSeedCluster() apiv1.SeedCluster {
	return apiv1.SeedCluster{ClusterID: r.ClusterID}
}

// adminListReq filters the admin token list.
// swagger:parameters listAllKubeconfigTokens
type adminListReq struct {
	// in: query
	// +optional
	ClusterID string `json:"cluster_id,omitempty"`
	// in: query
	// +optional
	UserID string `json:"user_id,omitempty"`
}

// adminTokenReq identifies one token without a project.
// swagger:parameters revokeAnyKubeconfigToken
type adminTokenReq struct {
	// in: path
	TokenID string `json:"token_id"`
}

func decodeProjectClusterReq(_ context.Context, r *http.Request) (interface{}, error) {
	return projectClusterReq{
		ProjectID: mux.Vars(r)["project_id"],
		ClusterID: mux.Vars(r)["cluster_id"],
	}, nil
}

func decodeTokenReq(_ context.Context, r *http.Request) (interface{}, error) {
	return tokenReq{
		ProjectID: mux.Vars(r)["project_id"],
		ClusterID: mux.Vars(r)["cluster_id"],
		TokenID:   mux.Vars(r)["token_id"],
	}, nil
}

func decodeTokenPatchReq(_ context.Context, r *http.Request) (interface{}, error) {
	req := tokenPatchReq{
		ProjectID: mux.Vars(r)["project_id"],
		ClusterID: mux.Vars(r)["cluster_id"],
		TokenID:   mux.Vars(r)["token_id"],
	}

	if err := json.NewDecoder(r.Body).Decode(&req.Body); err != nil {
		return nil, utilerrors.NewBadRequest("unable to decode the request body: %v", err)
	}

	return req, nil
}

func decodeAdminListReq(_ context.Context, r *http.Request) (interface{}, error) {
	return adminListReq{
		ClusterID: r.URL.Query().Get("cluster_id"),
		UserID:    r.URL.Query().Get("user_id"),
	}, nil
}

func decodeAdminTokenReq(_ context.Context, r *http.Request) (interface{}, error) {
	return adminTokenReq{
		TokenID: mux.Vars(r)["token_id"],
	}, nil
}
