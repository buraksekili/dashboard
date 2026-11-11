/*
Copyright 2022 The Kubermatic Kubernetes Platform contributors.

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

package webterminal_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	apiv1 "k8c.io/dashboard/v2/pkg/api/v1"
	handlercommon "k8c.io/dashboard/v2/pkg/handler/common"
	"k8c.io/dashboard/v2/pkg/handler/test"
	"k8c.io/dashboard/v2/pkg/handler/test/hack"
	"k8c.io/dashboard/v2/pkg/provider/kubernetes"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	testExpectedRedirectURI = ":///api/v2/kubeconfig/secret"
	testClusterName         = "AbcCluster"

	csrfCookieName = "csrf_token"
)

type ExpectedKubeconfigResp struct {
	BodyResponse string
	HTTPStatus   int
}

func TestCreateOIDCKubeconfig(t *testing.T) {
	t.Parallel()
	testcases := []struct {
		Name                      string
		ClusterID                 string
		ProjectID                 string
		UserID                    string
		State                     string
		NonceClaim                string
		HTTPStatusInitPhase       int
		ExistingKubermaticObjects []ctrlruntimeclient.Object
		ExistingObjects           []ctrlruntimeclient.Object
		ExistingAPIUser           *apiv1.User
		ExpectedRedirectURI       string
		ExpectedExchangeCodePhase ExpectedKubeconfigResp
	}{
		{
			Name:                      "scenario 1, no parameters for url",
			HTTPStatusInitPhase:       http.StatusInternalServerError,
			ExistingAPIUser:           test.GenDefaultAPIUser(),
			ExistingKubermaticObjects: genTestKubeconfigKubermaticObjects(),
			ExpectedExchangeCodePhase: ExpectedKubeconfigResp{},
		},
		{
			Name:                "scenario 2, incorrect user ID in state",
			ClusterID:           test.ClusterID,
			ProjectID:           test.GenDefaultProject().Name,
			UserID:              "0000",
			ExistingAPIUser:     test.GenDefaultAPIUser(),
			HTTPStatusInitPhase: http.StatusNotFound,
		},
		{
			Name:                      "scenario 3, exchange phase error: incorrect state parameter",
			ClusterID:                 test.ClusterID,
			ProjectID:                 test.GenDefaultProject().Name,
			UserID:                    test.GenDefaultUser().Name,
			State:                     "abc", // does not match the cookie
			HTTPStatusInitPhase:       http.StatusSeeOther,
			ExistingKubermaticObjects: genTestKubeconfigKubermaticObjects(),
			ExpectedRedirectURI:       testExpectedRedirectURI,
			ExistingAPIUser:           test.GenDefaultAPIUser(),
			ExpectedExchangeCodePhase: ExpectedKubeconfigResp{
				BodyResponse: fmt.Sprintf(`{"error":{"code":400,"message":"incorrect value of state parameter: abc"}}%c`, '\n'),
				HTTPStatus:   http.StatusBadRequest,
			},
		},
		{
			Name:                      "scenario 4, successful scenario",
			ClusterID:                 test.ClusterID,
			ProjectID:                 test.GenDefaultProject().Name,
			UserID:                    test.GenDefaultUser().Name,
			HTTPStatusInitPhase:       http.StatusSeeOther,
			ExistingKubermaticObjects: genTestKubeconfigKubermaticObjects(),
			ExistingObjects: []ctrlruntimeclient.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: kubernetes.NamespaceName(test.ClusterID),
						Name:      "admin-kubeconfig",
					},
					Data: map[string][]byte{
						"kubeconfig": []byte(test.GenerateTestKubeconfig(test.ClusterID, test.IDToken)),
					},
				},
			},
			ExpectedRedirectURI: testExpectedRedirectURI,
			ExistingAPIUser:     test.GenDefaultAPIUser(),
			ExpectedExchangeCodePhase: ExpectedKubeconfigResp{
				BodyResponse: "",
				HTTPStatus:   http.StatusOK,
			},
		},
		{
			Name:                      "scenario 5, the admin can get kubeconfig for Bob cluster",
			ClusterID:                 test.ClusterID,
			ProjectID:                 test.GenDefaultProject().Name,
			UserID:                    test.GenAdminUser("john", "john@acme.com", true).Name,
			HTTPStatusInitPhase:       http.StatusSeeOther,
			ExistingKubermaticObjects: genTestKubeconfigKubermaticObjects(),
			ExistingObjects: []ctrlruntimeclient.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: kubernetes.NamespaceName(test.ClusterID),
						Name:      "admin-kubeconfig",
					},
					Data: map[string][]byte{
						"kubeconfig": []byte(test.GenerateTestKubeconfig(test.ClusterID, test.IDToken)),
					},
				},
			},
			ExpectedRedirectURI: testExpectedRedirectURI,
			ExistingAPIUser:     test.GenAPIUser("john", "john@acme.com"),
			ExpectedExchangeCodePhase: ExpectedKubeconfigResp{
				BodyResponse: "",
				HTTPStatus:   http.StatusOK,
			},
		},
		{
			Name:                      "scenario 6, exchange phase error: ID token issued for a different nonce",
			ClusterID:                 test.ClusterID,
			ProjectID:                 test.GenDefaultProject().Name,
			UserID:                    test.GenDefaultUser().Name,
			HTTPStatusInitPhase:       http.StatusSeeOther,
			ExistingKubermaticObjects: genTestKubeconfigKubermaticObjects(),
			ExistingObjects: []ctrlruntimeclient.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: kubernetes.NamespaceName(test.ClusterID),
						Name:      "admin-kubeconfig",
					},
					Data: map[string][]byte{
						"kubeconfig": []byte(test.GenerateTestKubeconfig(test.ClusterID, test.IDToken)),
					},
				},
			},
			ExpectedRedirectURI: testExpectedRedirectURI,
			NonceClaim:          "nonce-of-another-login",
			ExistingAPIUser:     test.GenDefaultAPIUser(),
			ExpectedExchangeCodePhase: ExpectedKubeconfigResp{
				BodyResponse: "",
				HTTPStatus:   http.StatusBadRequest,
			},
		},
		{
			Name:                      "scenario 7, the web terminal is disabled",
			ClusterID:                 test.ClusterID,
			ProjectID:                 test.GenDefaultProject().Name,
			UserID:                    test.GenDefaultUser().Name,
			HTTPStatusInitPhase:       http.StatusForbidden,
			ExistingKubermaticObjects: genTestKubeconfigKubermaticObjectsWithTerminal(false),
			ExistingAPIUser:           test.GenDefaultAPIUser(),
		},
		{
			Name:                      "scenario 8, exchange phase error: the OIDC login belongs to a different user than user_id",
			ClusterID:                 test.ClusterID,
			ProjectID:                 test.GenDefaultProject().Name,
			UserID:                    test.GenDefaultUser().Name,
			HTTPStatusInitPhase:       http.StatusSeeOther,
			ExistingKubermaticObjects: genTestKubeconfigKubermaticObjects(),
			ExpectedRedirectURI:       testExpectedRedirectURI,
			// the identity provider login is done by John, not by the user in user_id
			ExistingAPIUser: test.GenAPIUser("john", "john@acme.com"),
			ExpectedExchangeCodePhase: ExpectedKubeconfigResp{
				BodyResponse: "",
				HTTPStatus:   http.StatusForbidden,
			},
		},
		{
			Name:                      "scenario 9, the OIDC login email differs from the email of the user only in case",
			ClusterID:                 test.ClusterID,
			ProjectID:                 test.GenDefaultProject().Name,
			UserID:                    test.GenDefaultUser().Name,
			HTTPStatusInitPhase:       http.StatusSeeOther,
			ExistingKubermaticObjects: genTestKubeconfigKubermaticObjects(),
			ExistingObjects: []ctrlruntimeclient.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: kubernetes.NamespaceName(test.ClusterID),
						Name:      "admin-kubeconfig",
					},
					Data: map[string][]byte{
						"kubeconfig": []byte(test.GenerateTestKubeconfig(test.ClusterID, test.IDToken)),
					},
				},
			},
			ExpectedRedirectURI: testExpectedRedirectURI,
			// test.GenAPIUser lowercases the email
			ExistingAPIUser: &apiv1.User{
				ObjectMeta: apiv1.ObjectMeta{ID: test.GenDefaultUser().Name, Name: "Bob"},
				Email:      "Bob@Acme.com",
			},
			ExpectedExchangeCodePhase: ExpectedKubeconfigResp{
				BodyResponse: "",
				HTTPStatus:   http.StatusOK,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			reqURL := fmt.Sprintf("/api/v2/kubeconfig/secret?cluster_id=%s&project_id=%s&user_id=%s", tc.ClusterID, tc.ProjectID, tc.UserID)
			req := httptest.NewRequest(http.MethodGet, reqURL, strings.NewReader(""))
			res := httptest.NewRecorder()
			ep, clients, err := test.CreateTestEndpointAndGetClients(*tc.ExistingAPIUser, nil, tc.ExistingObjects, nil, tc.ExistingKubermaticObjects, nil, hack.NewTestRouting)
			if err != nil {
				t.Fatalf("failed to create test endpoint: %v", err)
			}
			clients.FakeOIDCClient.SetNonceClaim(tc.NonceClaim)

			// act
			ep.ServeHTTP(res, req)
			result := res.Result()
			defer result.Body.Close()

			// validate
			assert.Equal(t, tc.HTTPStatusInitPhase, res.Code)

			// Redirection to dex provider
			if res.Code == http.StatusSeeOther {
				location, err := result.Location()
				if err != nil {
					t.Fatalf("expected url for redirection %v", err)
				}

				// validate
				redirectURI := location.Query().Get("redirect_uri")
				assert.Equal(t, tc.ExpectedRedirectURI, redirectURI)
				assert.Equal(t, "S256", location.Query().Get("code_challenge_method"))
				assert.NotEmpty(t, location.Query().Get("nonce"))

				encodedState, err := url.QueryUnescape(location.Query().Get("state"))
				if err != nil {
					t.Fatalf("incorrect state format %v", err)
				}
				decodeState, err := base64.StdEncoding.DecodeString(encodedState)
				if err != nil {
					t.Fatalf("error decoding state %v", err)
				}

				state, err := unmarshalState(decodeState)
				if err != nil {
					t.Fatalf("error unmarshal state %v", err)
				}

				// validate
				assert.Equal(t, tc.ClusterID, state.ClusterID)
				assert.Equal(t, tc.ProjectID, state.ProjectID)
				assert.Equal(t, tc.UserID, state.UserID)

				// override the State if test scenario set the value
				// if not use generated by server
				if tc.State != "" {
					state.State = tc.State
				}

				encodedState, err = marshalEncodeState(state)
				if err != nil {
					t.Fatalf("error marshal state %v", err)
				}
				urlExchangeCodePhase := fmt.Sprintf("/api/v2/kubeconfig/secret?code=%s&state=%s", test.AuthorizationCode, encodedState)

				// call kubeconfig endpoint after authentication
				// exchange code phase
				req = httptest.NewRequest(http.MethodGet, urlExchangeCodePhase, strings.NewReader(""))
				res = httptest.NewRecorder()

				// forward the cookie (nonce and PKCE verifier) set by the server in the initial phase
				for _, cookie := range result.Cookies() {
					if cookie.Name == csrfCookieName {
						req.AddCookie(cookie)
					}
				}

				// act
				ep.ServeHTTP(res, req)
				defer res.Result().Body.Close()

				// validate
				assert.Equal(t, tc.ExpectedExchangeCodePhase.HTTPStatus, res.Code)
			}
		})
	}
}

func TestTerminalRequestIsRejected(t *testing.T) {
	t.Parallel()
	testcases := []struct {
		Name                      string
		ExistingKubermaticObjects []ctrlruntimeclient.Object
		ExistingAPIUser           *apiv1.User
		ExpectedHTTPStatus        int
	}{
		{
			Name:                      "the web terminal is disabled",
			ExistingKubermaticObjects: genTestKubeconfigKubermaticObjectsWithTerminal(false),
			ExistingAPIUser:           test.GenDefaultAPIUser(),
			ExpectedHTTPStatus:        http.StatusForbidden,
		},
		{
			Name:                      "the user is not a member of the project",
			ExistingKubermaticObjects: append(genTestKubeconfigKubermaticObjects(), test.GenUser("", "alice", "alice@acme.com")),
			ExistingAPIUser:           test.GenAPIUser("alice", "alice@acme.com"),
			ExpectedHTTPStatus:        http.StatusForbidden,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Name, func(t *testing.T) {
			reqURL := fmt.Sprintf("/api/v1/ws/projects/%s/clusters/%s/terminal", test.GenDefaultProject().Name, test.ClusterID)
			req := httptest.NewRequest(http.MethodGet, reqURL, strings.NewReader(""))
			res := httptest.NewRecorder()
			ep, err := test.CreateTestEndpoint(*tc.ExistingAPIUser, nil, tc.ExistingKubermaticObjects, nil, hack.NewTestRouting)
			if err != nil {
				t.Fatalf("failed to create test endpoint: %v", err)
			}

			ep.ServeHTTP(res, req)

			assert.Equal(t, tc.ExpectedHTTPStatus, res.Code)
		})
	}
}

func genTestKubeconfigKubermaticObjects() []ctrlruntimeclient.Object {
	return genTestKubeconfigKubermaticObjectsWithTerminal(true)
}

func genTestKubeconfigKubermaticObjectsWithTerminal(webTerminalEnabled bool) []ctrlruntimeclient.Object {
	return []ctrlruntimeclient.Object{
		&kubermaticv1.KubermaticSetting{
			ObjectMeta: metav1.ObjectMeta{Name: kubermaticv1.GlobalSettingsName},
			Spec: kubermaticv1.SettingSpec{
				WebTerminalOptions: &kubermaticv1.WebTerminalOptions{Enabled: &webTerminalEnabled},
			},
		},
		test.GenTestSeed(),
		// add some project
		test.GenDefaultProject(),
		// add a user
		test.GenDefaultUser(),
		test.GenAdminUser("john", "john@acme.com", true),
		// make the user the owner of the first project and the editor of the second
		test.GenDefaultOwnerBinding(),
		// add a cluster
		test.GenCluster(test.ClusterID, testClusterName, test.GenDefaultProject().Name, test.DefaultCreationTimestamp()),
	}
}

func marshalEncodeState(oidcState handlercommon.OIDCState) (string, error) {
	rawState, err := json.Marshal(oidcState)
	if err != nil {
		return "", err
	}
	encodedState := base64.StdEncoding.EncodeToString(rawState)
	return url.QueryEscape(encodedState), nil
}

func unmarshalState(rawState []byte) (handlercommon.OIDCState, error) {
	oidcState := handlercommon.OIDCState{}
	if err := json.Unmarshal(rawState, &oidcState); err != nil {
		return handlercommon.OIDCState{}, err
	}
	return oidcState, nil
}

func TestCreateOIDCKubeconfigSecretRedirectURI(t *testing.T) {
	t.Parallel()
	const (
		mainWithPort   = "https://kkp.example.com:443/api/v1/kubeconfig"
		mainCustomPath = "https://kkp.example.com/custom/kubeconfig"
	)

	testcases := []struct {
		name                string
		redirectURI         string
		origin              string
		dropStoredRedirect  bool
		expectedRedirectURI string
	}{
		{
			name:                "no origin keeps the main hostname with explicit port",
			redirectURI:         mainWithPort,
			expectedRedirectURI: "https://kkp.example.com:443/api/v2/kubeconfig/secret",
		},
		{
			name:                "main hostname origin keeps the main hostname with explicit port",
			redirectURI:         mainWithPort,
			origin:              "https://kkp.example.com",
			expectedRedirectURI: "https://kkp.example.com:443/api/v2/kubeconfig/secret",
		},
		{
			name:                "main hostname origin with a configured custom path",
			redirectURI:         mainCustomPath,
			origin:              "https://kkp.example.com",
			expectedRedirectURI: "https://kkp.example.com/api/v2/kubeconfig/secret",
		},
		{
			name:                "additional origin redirects back to the proxy hostname",
			redirectURI:         mainWithPort,
			origin:              "https://kkp-proxy.example.com",
			expectedRedirectURI: "https://kkp-proxy.example.com/api/v2/kubeconfig/secret",
		},
		{
			name:                "unlisted origin keeps the main hostname",
			redirectURI:         mainWithPort,
			origin:              "https://evil.example.com",
			expectedRedirectURI: "https://kkp.example.com:443/api/v2/kubeconfig/secret",
		},
		{
			name:                "cookie without a redirect URI from before the upgrade uses the main hostname",
			redirectURI:         mainWithPort,
			dropStoredRedirect:  true,
			expectedRedirectURI: "https://kkp.example.com:443/api/v2/kubeconfig/secret",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ep, clients, err := test.CreateTestEndpointAndGetClients(*test.GenDefaultAPIUser(), nil, []ctrlruntimeclient.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: kubernetes.NamespaceName(test.ClusterID),
						Name:      "admin-kubeconfig",
					},
					Data: map[string][]byte{
						"kubeconfig": []byte(test.GenerateTestKubeconfig(test.ClusterID, test.IDToken)),
					},
				},
			}, nil, genTestKubeconfigKubermaticObjects(), nil, hack.NewTestRouting)
			if err != nil {
				t.Fatalf("failed to create test endpoint: %v", err)
			}
			clients.FakeOIDCClient.SetRedirectURI(tc.redirectURI)
			clients.FakeOIDCClient.SetAdditionalRedirectURIs("https://kkp-proxy.example.com")

			reqURL := fmt.Sprintf("/api/v2/kubeconfig/secret?cluster_id=%s&project_id=%s&user_id=%s&origin=%s", test.ClusterID, test.GenDefaultProject().Name, test.GenDefaultUser().Name, url.QueryEscape(tc.origin))
			res := httptest.NewRecorder()
			ep.ServeHTTP(res, httptest.NewRequest(http.MethodGet, reqURL, nil))
			if res.Code != http.StatusSeeOther {
				t.Fatalf("expected status %d, got %d: %s", http.StatusSeeOther, res.Code, res.Body.String())
			}

			location, err := res.Result().Location()
			if err != nil {
				t.Fatalf("expected url for redirection: %v", err)
			}
			assert.Equal(t, tc.expectedRedirectURI, location.Query().Get("redirect_uri"))

			cookie := test.GetCookie(res.Result().Cookies(), csrfCookieName)
			if cookie == nil {
				t.Fatalf("cookie %q not set", csrfCookieName)
			}
			if tc.dropStoredRedirect {
				if cookie, err = test.WithoutStoredRedirectURI(cookie); err != nil {
					t.Fatalf("failed to re-sign the state cookie: %v", err)
				}
			}

			// the fake provider rejects a token request whose redirect_uri differs from the authorization request
			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v2/kubeconfig/secret?code=%s&state=%s", test.AuthorizationCode, url.QueryEscape(location.Query().Get("state"))), nil)
			req.AddCookie(cookie)
			res = httptest.NewRecorder()
			ep.ServeHTTP(res, req)
			assert.Equal(t, http.StatusOK, res.Code, res.Body.String())
		})
	}
}
