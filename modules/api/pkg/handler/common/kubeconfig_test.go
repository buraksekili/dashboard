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

package common

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlruntimefake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestEncodeUserEmailToIDIgnoresCase(t *testing.T) {
	require.Equal(t, EncodeUserEmailToID("bob@acme.com"), EncodeUserEmailToID("Bob@ACME.com"))
	require.NotEqual(t, EncodeUserEmailToID("bob@acme.com"), EncodeUserEmailToID("alice@acme.com"))
}

func TestBuildWebTerminalKubeconfig(t *testing.T) {
	cluster := clientcmdapi.NewCluster()
	cluster.Server = "https://apiserver.example.com:6443"
	cluster.CertificateAuthorityData = []byte("ca-data")

	cfg := buildWebTerminalKubeconfig("abc123", cluster, "bob@acme.com", "the-id-token")

	authInfo, ok := cfg.AuthInfos["bob@acme.com"]
	require.True(t, ok, "expected auth info for the user")
	require.Equal(t, "the-id-token", authInfo.Token)
	require.Nil(t, authInfo.AuthProvider)
	require.Equal(t, "abc123", cfg.CurrentContext)
	require.Equal(t, "bob@acme.com", cfg.Contexts["abc123"].AuthInfo)
	require.Equal(t, cluster.Server, cfg.Clusters["abc123"].Server)

	raw, err := clientcmd.Write(*cfg)
	require.NoError(t, err)
	for _, forbidden := range []string{"auth-provider", "refresh-token", "client-secret", "client-id"} {
		require.False(t, strings.Contains(string(raw), forbidden), "kubeconfig must not contain %q:\n%s", forbidden, raw)
	}
	require.Contains(t, string(raw), "token: the-id-token")
}

func TestWriteWebTerminalOIDCSecret(t *testing.T) {
	ctx := context.Background()
	seedClient := ctrlruntimefake.NewClientBuilder().Build()
	userEmailID := EncodeUserEmailToID("bob@acme.com")
	key := types.NamespacedName{Namespace: "cluster-abc123", Name: WebTerminalOIDCSecretName(userEmailID)}

	require.NoError(t, writeWebTerminalOIDCSecret(ctx, seedClient, "cluster-abc123", userEmailID, "bob@acme.com", "refresh-1"))

	secret := &corev1.Secret{}
	require.NoError(t, seedClient.Get(ctx, key, secret))
	require.Equal(t, "refresh-1", string(secret.Data[WebTerminalOIDCRefreshTokenKey]))
	require.Equal(t, "webterminal-oidc-"+userEmailID, secret.Name)

	// a second login replaces the refresh token and keeps existing owner references
	secret.OwnerReferences = []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: "cleanup", UID: "uid-1"}}
	require.NoError(t, seedClient.Update(ctx, secret))

	require.NoError(t, writeWebTerminalOIDCSecret(ctx, seedClient, "cluster-abc123", userEmailID, "bob@acme.com", "refresh-2"))
	require.NoError(t, seedClient.Get(ctx, key, secret))
	require.Equal(t, "refresh-2", string(secret.Data[WebTerminalOIDCRefreshTokenKey]))
	require.Len(t, secret.OwnerReferences, 1)
}

func TestWriteWebTerminalOIDCSecretRetriesOnAlreadyExists(t *testing.T) {
	ctx := context.Background()
	userEmailID := EncodeUserEmailToID("bob@acme.com")
	existing := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "cluster-abc123", Name: WebTerminalOIDCSecretName(userEmailID)}}

	// the first Get misses the Secret, as if another request created it in between
	missed := false
	seedClient := ctrlruntimefake.NewClientBuilder().WithObjects(existing).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(ctx context.Context, c ctrlruntimeclient.WithWatch, key ctrlruntimeclient.ObjectKey, obj ctrlruntimeclient.Object, opts ...ctrlruntimeclient.GetOption) error {
			if !missed {
				missed = true
				return apierrors.NewNotFound(corev1.Resource("secrets"), key.Name)
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}).Build()

	require.NoError(t, writeWebTerminalOIDCSecret(ctx, seedClient, "cluster-abc123", userEmailID, "bob@acme.com", "refresh-1"))

	secret := &corev1.Secret{}
	require.NoError(t, seedClient.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(existing), secret))
	require.Equal(t, "refresh-1", string(secret.Data[WebTerminalOIDCRefreshTokenKey]))
}

func TestClusterFromAdminKubeconfig(t *testing.T) {
	adminCfg := clientcmdapi.NewConfig()
	adminCfg.Clusters["other"] = &clientcmdapi.Cluster{Server: "https://other"}
	adminCfg.Clusters["abc123"] = &clientcmdapi.Cluster{Server: "https://internal", CertificateAuthorityData: []byte("ca")}

	// run a few times, map iteration order is random
	for range 20 {
		c := clusterFromAdminKubeconfig(adminCfg, "abc123", "https://external")
		require.NotNil(t, c)
		require.Equal(t, "https://external", c.Server)
		require.Equal(t, []byte("ca"), c.CertificateAuthorityData)
		require.Equal(t, "https://other", adminCfg.Clusters["other"].Server)
	}

	require.Nil(t, clusterFromAdminKubeconfig(adminCfg, "missing", "https://external"))

	c := clusterFromAdminKubeconfig(adminCfg, "abc123", "")
	require.Equal(t, "https://internal", c.Server)
}
