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
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	handlercommon "k8c.io/dashboard/v2/pkg/handler/common"
	authtypes "k8c.io/dashboard/v2/pkg/provider/auth/types"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlruntimefake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

const (
	testEmail     = "Bob@Acme.com"
	testClusterID = "abc123"
	// deliberately not "cluster-<id>", the code must use cluster.Status.NamespaceName.
	testClusterNS = "cluster-ns-abc123"
)

func TestEncodeUserEmailtoIDIgnoresCase(t *testing.T) {
	require.Equal(t, EncodeUserEmailtoID("bob@acme.com"), EncodeUserEmailtoID(testEmail))
	require.Equal(t, handlercommon.EncodeUserEmailToID("bob@acme.com"), EncodeUserEmailtoID(testEmail))
}

func TestGenWebTerminalCleanupJobDeletesKubeconfigSecret(t *testing.T) {
	userEmailID := EncodeUserEmailtoID(testEmail)
	job := genWebTerminalCleanupJob(userAppName(userEmailID), userEmailID, testClusterNS, "")
	require.Equal(t, testClusterNS, job.Namespace)

	container := job.Spec.Template.Spec.Containers[0]
	env := map[string]string{}
	for _, e := range container.Env {
		env[e.Name] = e.Value
	}
	require.Equal(t, handlercommon.KubeconfigSecretName(userEmailID), env["KUBECONFIG_SECRET_NAME"])

	script := strings.Join(container.Args, "\n")
	for _, cmd := range []string{
		"kubectl delete secret $KUBECONFIG_SECRET_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1",
		"kubectl delete networkpolicy $USER_APP_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1",
		"kubectl delete configmap $USER_APP_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1",
		"kubectl delete pod $USER_APP_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1",
		"exit $rc",
	} {
		require.Contains(t, script, cmd)
	}
}

// fakeJWT returns an unsigned JWT with the given expiry. Only the payload is parsed.
func fakeJWT(exp time.Time) string {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"none"}`))
	payload := enc.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix())))
	return header + "." + payload + ".sig"
}

// fakeJWTWithIat returns an unsigned JWT with issue and expiry times.
func fakeJWTWithIat(iat, exp time.Time) string {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"none"}`))
	payload := enc.EncodeToString([]byte(fmt.Sprintf(`{"iat":%d,"exp":%d}`, iat.Unix(), exp.Unix())))
	return header + "." + payload + ".sig"
}

func TestTokenRefreshThreshold(t *testing.T) {
	now := time.Now()
	require.Equal(t, 150*time.Second, tokenRefreshThreshold(fakeJWTWithIat(now, now.Add(5*time.Minute))))
	require.Equal(t, 5*time.Minute, tokenRefreshThreshold(fakeJWTWithIat(now, now.Add(time.Hour))))
	require.Equal(t, 5*time.Minute, tokenRefreshThreshold(fakeJWT(now.Add(time.Hour))))
	require.Equal(t, 5*time.Minute, tokenRefreshThreshold("not-a-token"))
}

type fakeRefresher struct {
	authtypes.OIDCIssuerVerifier

	mu           sync.Mutex
	newToken     authtypes.OIDCToken
	err          error
	usedRefresh  []string
	refreshCalls int
}

func (f *fakeRefresher) RefreshAccessToken(_ context.Context, refreshToken string) (authtypes.OIDCToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshCalls++
	f.usedRefresh = append(f.usedRefresh, refreshToken)
	return f.newToken, f.err
}

func (f *fakeRefresher) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshCalls
}

type fakeWriter struct {
	mu       sync.Mutex
	messages []string
}

func (w *fakeWriter) WriteJSON(v interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if msg, ok := v.(TerminalMessage); ok {
		w.messages = append(w.messages, msg.Data)
	}
	return nil
}

func (w *fakeWriter) has(msg string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, m := range w.messages {
		if m == msg {
			return true
		}
	}
	return false
}

func genUserKubeconfigSecret(t *testing.T, userEmailID, idToken string) *corev1.Secret {
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters[testClusterID] = &clientcmdapi.Cluster{Server: "https://apiserver.example.com"}
	cfg.AuthInfos["bob@acme.com"] = &clientcmdapi.AuthInfo{Token: idToken}
	cfg.Contexts[testClusterID] = &clientcmdapi.Context{Cluster: testClusterID, AuthInfo: "bob@acme.com"}
	cfg.CurrentContext = testClusterID
	raw, err := clientcmd.Write(*cfg)
	require.NoError(t, err)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: handlercommon.KubeconfigSecretName(userEmailID), Namespace: metav1.NamespaceSystem},
		Data:       map[string][]byte{"kubeconfig": raw},
	}
}

func genSeedOIDCSecret(userEmailID, refreshToken string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: handlercommon.WebTerminalOIDCSecretName(userEmailID), Namespace: testClusterNS},
		Data:       map[string][]byte{handlercommon.WebTerminalOIDCRefreshTokenKey: []byte(refreshToken)},
	}
}

func TestCheckTokenAndRefreshIfNeeded(t *testing.T) {
	userEmailID := EncodeUserEmailtoID(testEmail)
	clusterClient := ctrlruntimefake.NewClientBuilder().WithObjects(genUserKubeconfigSecret(t, userEmailID, fakeJWT(time.Now().Add(time.Minute)))).Build()
	seedClient := ctrlruntimefake.NewClientBuilder().WithObjects(genSeedOIDCSecret(userEmailID, "refresh-old")).Build()

	newIDToken := fakeJWT(time.Now().Add(time.Hour))
	verifier := &fakeRefresher{newToken: authtypes.OIDCToken{IDToken: newIDToken, RefreshToken: "refresh-new"}}
	writer := &fakeWriter{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		checkTokenAndRefreshIfNeeded(ctx, clusterClient, seedClient, testClusterNS, userEmailID, verifier, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: handlercommon.KubeconfigSecretName(userEmailID)}}, writer)
	}()

	require.Eventually(t, func() bool { return writer.has(string(WebTerminalTokenValid)) }, 5*time.Second, 10*time.Millisecond)

	verifier.mu.Lock()
	require.Equal(t, 1, verifier.refreshCalls)
	require.Equal(t, []string{"refresh-old"}, verifier.usedRefresh)
	verifier.mu.Unlock()

	seedSecret := &corev1.Secret{}
	require.NoError(t, seedClient.Get(context.Background(), types.NamespacedName{Namespace: testClusterNS, Name: handlercommon.WebTerminalOIDCSecretName(userEmailID)}, seedSecret))
	require.Equal(t, "refresh-new", string(seedSecret.Data[handlercommon.WebTerminalOIDCRefreshTokenKey]))

	userSecret := &corev1.Secret{}
	require.NoError(t, clusterClient.Get(context.Background(), types.NamespacedName{Namespace: metav1.NamespaceSystem, Name: handlercommon.KubeconfigSecretName(userEmailID)}, userSecret))
	cfg, err := clientcmd.Load(userSecret.Data["kubeconfig"])
	require.NoError(t, err)
	require.Equal(t, newIDToken, cfg.AuthInfos["bob@acme.com"].Token)
	require.Nil(t, cfg.AuthInfos["bob@acme.com"].AuthProvider)
	require.NotContains(t, string(userSecret.Data["kubeconfig"]), "refresh")

	// the loop now sleeps until shortly before the new token expires, cancel must stop it
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh loop did not return after context cancel")
	}
}

func TestCheckTokenAndRefreshIfNeededStopsWhileSecretMissing(t *testing.T) {
	userEmailID := EncodeUserEmailtoID(testEmail)
	clusterClient := ctrlruntimefake.NewClientBuilder().Build()
	seedClient := ctrlruntimefake.NewClientBuilder().Build()
	writer := &fakeWriter{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		checkTokenAndRefreshIfNeeded(ctx, clusterClient, seedClient, testClusterNS, userEmailID, &fakeRefresher{}, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: handlercommon.KubeconfigSecretName(userEmailID)}}, writer)
	}()

	require.Eventually(t, func() bool { return writer.has(string(KubeconfigSecretMissing)) }, 5*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh loop did not return after context cancel")
	}
}

// runRefreshLoop starts the refresh loop and returns a function that cancels it and fails the test
// if the loop does not return promptly.
func runRefreshLoop(t *testing.T, clusterClient, seedClient ctrlruntimeclient.Client, verifier authtypes.OIDCIssuerVerifier, writer *fakeWriter) func() {
	userEmailID := EncodeUserEmailtoID(testEmail)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		checkTokenAndRefreshIfNeeded(ctx, clusterClient, seedClient, testClusterNS, userEmailID, verifier, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: handlercommon.KubeconfigSecretName(userEmailID)}}, writer)
	}()

	return func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("refresh loop did not return after context cancel")
		}
	}
}

func TestCheckTokenAndRefreshIfNeededShortLivedToken(t *testing.T) {
	userEmailID := EncodeUserEmailtoID(testEmail)
	now := time.Now()

	// a 5 minute token with 3 minutes left is not refreshed yet, the threshold is 2.5 minutes
	clusterClient := ctrlruntimefake.NewClientBuilder().WithObjects(genUserKubeconfigSecret(t, userEmailID, fakeJWTWithIat(now.Add(-2*time.Minute), now.Add(3*time.Minute)))).Build()
	seedClient := ctrlruntimefake.NewClientBuilder().WithObjects(genSeedOIDCSecret(userEmailID, "refresh-old")).Build()
	verifier := &fakeRefresher{newToken: authtypes.OIDCToken{IDToken: fakeJWTWithIat(now, now.Add(5*time.Minute)), RefreshToken: "refresh-new"}}
	writer := &fakeWriter{}
	stop := runRefreshLoop(t, clusterClient, seedClient, verifier, writer)
	require.Eventually(t, func() bool { return writer.has(string(WebTerminalTokenValid)) }, 5*time.Second, 10*time.Millisecond)
	stop()
	require.Equal(t, 0, verifier.calls())

	// the same token with 2m20s left is refreshed
	clusterClient = ctrlruntimefake.NewClientBuilder().WithObjects(genUserKubeconfigSecret(t, userEmailID, fakeJWTWithIat(now.Add(-160*time.Second), now.Add(140*time.Second)))).Build()
	writer = &fakeWriter{}
	stop = runRefreshLoop(t, clusterClient, seedClient, verifier, writer)
	require.Eventually(t, func() bool { return writer.has(string(WebTerminalTokenValid)) }, 5*time.Second, 10*time.Millisecond)
	stop()
	require.Equal(t, 1, verifier.calls())
}

func TestCheckTokenAndRefreshIfNeededDeletesLegacySecret(t *testing.T) {
	userEmailID := EncodeUserEmailtoID(testEmail)

	cfg := clientcmdapi.NewConfig()
	cfg.AuthInfos["bob@acme.com"] = &clientcmdapi.AuthInfo{AuthProvider: &clientcmdapi.AuthProviderConfig{
		Name:   "oidc",
		Config: map[string]string{"id-token": fakeJWT(time.Now().Add(time.Hour)), "refresh-token": "refresh", "client-secret": "secret"},
	}}
	raw, err := clientcmd.Write(*cfg)
	require.NoError(t, err)
	legacy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: handlercommon.KubeconfigSecretName(userEmailID), Namespace: metav1.NamespaceSystem},
		Data:       map[string][]byte{"kubeconfig": raw},
	}
	require.True(t, IsLegacyKubeconfigSecret(legacy))
	require.False(t, IsLegacyKubeconfigSecret(genUserKubeconfigSecret(t, userEmailID, "token")))

	clusterClient := ctrlruntimefake.NewClientBuilder().WithObjects(legacy).Build()
	writer := &fakeWriter{}
	stop := runRefreshLoop(t, clusterClient, ctrlruntimefake.NewClientBuilder().Build(), &fakeRefresher{}, writer)
	require.Eventually(t, func() bool { return writer.has(string(KubeconfigSecretMissing)) }, 5*time.Second, 10*time.Millisecond)
	stop()

	err = clusterClient.Get(context.Background(), ctrlruntimeclient.ObjectKeyFromObject(legacy), &corev1.Secret{})
	require.True(t, apierrors.IsNotFound(err), "expected legacy secret to be deleted, got %v", err)
}

func TestCheckTokenAndRefreshIfNeededMissingSeedSecret(t *testing.T) {
	userEmailID := EncodeUserEmailtoID(testEmail)
	clusterClient := ctrlruntimefake.NewClientBuilder().WithObjects(genUserKubeconfigSecret(t, userEmailID, fakeJWT(time.Now().Add(-time.Minute)))).Build()
	verifier := &fakeRefresher{}
	writer := &fakeWriter{}

	stop := runRefreshLoop(t, clusterClient, ctrlruntimefake.NewClientBuilder().Build(), verifier, writer)
	require.Eventually(t, func() bool { return writer.has(string(WebTerminalTokenExpired)) }, 5*time.Second, 10*time.Millisecond)
	stop()
	require.Equal(t, 0, verifier.calls())
}

func TestCheckTokenAndRefreshIfNeededFailedRefresh(t *testing.T) {
	userEmailID := EncodeUserEmailtoID(testEmail)
	oldToken := fakeJWT(time.Now().Add(-time.Minute))
	clusterClient := ctrlruntimefake.NewClientBuilder().WithObjects(genUserKubeconfigSecret(t, userEmailID, oldToken)).Build()
	seedClient := ctrlruntimefake.NewClientBuilder().WithObjects(genSeedOIDCSecret(userEmailID, "refresh-old")).Build()
	verifier := &fakeRefresher{err: errors.New("invalid_grant")}
	writer := &fakeWriter{}

	stop := runRefreshLoop(t, clusterClient, seedClient, verifier, writer)
	require.Eventually(t, func() bool { return writer.has(string(WebTerminalTokenExpired)) }, 5*time.Second, 10*time.Millisecond)
	stop()
	require.GreaterOrEqual(t, verifier.calls(), 1)

	seedSecret := &corev1.Secret{}
	require.NoError(t, seedClient.Get(context.Background(), types.NamespacedName{Namespace: testClusterNS, Name: handlercommon.WebTerminalOIDCSecretName(userEmailID)}, seedSecret))
	require.Equal(t, "refresh-old", string(seedSecret.Data[handlercommon.WebTerminalOIDCRefreshTokenKey]))

	userSecret := &corev1.Secret{}
	require.NoError(t, clusterClient.Get(context.Background(), types.NamespacedName{Namespace: metav1.NamespaceSystem, Name: handlercommon.KubeconfigSecretName(userEmailID)}, userSecret))
	cfg, err := clientcmd.Load(userSecret.Data["kubeconfig"])
	require.NoError(t, err)
	require.Equal(t, oldToken, cfg.AuthInfos["bob@acme.com"].Token)
}

func genTestCluster() *kubermaticv1.Cluster {
	cluster := &kubermaticv1.Cluster{ObjectMeta: metav1.ObjectMeta{Name: testClusterID}}
	cluster.Status.NamespaceName = testClusterNS
	cluster.Status.Address.IP = "10.0.0.1"
	cluster.Status.Address.Port = 6443
	cluster.Spec.ClusterNetwork.Services.CIDRBlocks = []string{"10.240.16.0/20"}
	return cluster
}

// seedClientWithUIDs returns a fake seed client that sets a UID on created objects like a real API server.
func seedClientWithUIDs(objs ...ctrlruntimeclient.Object) ctrlruntimeclient.Client {
	return ctrlruntimefake.NewClientBuilder().WithObjects(objs...).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c ctrlruntimeclient.WithWatch, obj ctrlruntimeclient.Object, opts ...ctrlruntimeclient.CreateOption) error {
			obj.SetUID(types.UID("uid-" + obj.GetName()))
			return c.Create(ctx, obj, opts...)
		},
	}).Build()
}

func seedSecretOwners(t *testing.T, seedClient ctrlruntimeclient.Client) []metav1.OwnerReference {
	secret := &corev1.Secret{}
	require.NoError(t, seedClient.Get(context.Background(), types.NamespacedName{Namespace: testClusterNS, Name: handlercommon.WebTerminalOIDCSecretName(EncodeUserEmailtoID(testEmail))}, secret))
	return secret.OwnerReferences
}

func TestPrepareResourcesSetsSeedSecretOwner(t *testing.T) {
	ctx := context.Background()
	userEmailID := EncodeUserEmailtoID(testEmail)
	appName := userAppName(userEmailID)
	jobName := "cleanup-" + appName

	clusterClient := ctrlruntimefake.NewClientBuilder().Build()
	seedClient := seedClientWithUIDs(genSeedOIDCSecret(userEmailID, "refresh"))

	require.NoError(t, prepareResources(ctx, clusterClient, seedClient, userEmailID, appName, genTestCluster(), nil, ""))

	refs := seedSecretOwners(t, seedClient)
	require.Len(t, refs, 1)
	ref := refs[0]
	require.Equal(t, "batch/v1", ref.APIVersion)
	require.Equal(t, "Job", ref.Kind)
	require.Equal(t, jobName, ref.Name)
	require.Equal(t, types.UID("uid-"+jobName), ref.UID)
	require.False(t, *ref.Controller)
	require.False(t, *ref.BlockOwnerDeletion)

	// a second session finds the pod and the job, the reference must not be duplicated
	require.NoError(t, prepareResources(ctx, clusterClient, seedClient, userEmailID, appName, genTestCluster(), nil, ""))
	require.Len(t, seedSecretOwners(t, seedClient), 1)
}

func TestPrepareResourcesExistingPodWithoutJob(t *testing.T) {
	ctx := context.Background()
	userEmailID := EncodeUserEmailtoID(testEmail)
	appName := userAppName(userEmailID)
	jobName := "cleanup-" + appName

	// the pod outlived its job, for example while the old pod is still terminating
	pod := genWebTerminalPod(appName, userEmailID, nil, "")
	clusterClient := ctrlruntimefake.NewClientBuilder().WithObjects(pod).Build()
	seedClient := seedClientWithUIDs(genSeedOIDCSecret(userEmailID, "refresh"))

	require.NoError(t, prepareResources(ctx, clusterClient, seedClient, userEmailID, appName, genTestCluster(), nil, ""))

	job := &batchv1.Job{}
	require.NoError(t, seedClient.Get(ctx, types.NamespacedName{Namespace: testClusterNS, Name: jobName}, job))
	refs := seedSecretOwners(t, seedClient)
	require.Len(t, refs, 1)
	require.Equal(t, job.UID, refs[0].UID)
}

func TestPrepareResourcesReplacesLegacyJob(t *testing.T) {
	ctx := context.Background()
	userEmailID := EncodeUserEmailtoID(testEmail)
	appName := userAppName(userEmailID)

	// a job created before the upgrade, its script does not delete the kubeconfig secret
	legacyJob := genWebTerminalCleanupJob(appName, userEmailID, testClusterNS, "")
	legacyJob.UID = "uid-legacy"
	container := &legacyJob.Spec.Template.Spec.Containers[0]
	env := []corev1.EnvVar{}
	for _, e := range container.Env {
		if e.Name != "KUBECONFIG_SECRET_NAME" {
			env = append(env, e)
		}
	}
	container.Env = env

	clusterClient := ctrlruntimefake.NewClientBuilder().Build()
	seedClient := seedClientWithUIDs(legacyJob, genSeedOIDCSecret(userEmailID, "refresh"))

	require.NoError(t, prepareResources(ctx, clusterClient, seedClient, userEmailID, appName, genTestCluster(), nil, ""))

	job := &batchv1.Job{}
	require.NoError(t, seedClient.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(legacyJob), job))
	require.NotEqual(t, types.UID("uid-legacy"), job.UID)
	require.True(t, cleanupJobDeletesKubeconfigSecret(job))
	refs := seedSecretOwners(t, seedClient)
	require.Len(t, refs, 1)
	require.Equal(t, job.UID, refs[0].UID)
}

func TestPrepareResourcesWithoutSeedSecret(t *testing.T) {
	ctx := context.Background()
	userEmailID := EncodeUserEmailtoID(testEmail)
	appName := userAppName(userEmailID)

	seedClient := seedClientWithUIDs()
	require.NoError(t, prepareResources(ctx, ctrlruntimefake.NewClientBuilder().Build(), seedClient, userEmailID, appName, genTestCluster(), nil, ""))

	job := &batchv1.Job{}
	require.NoError(t, seedClient.Get(ctx, types.NamespacedName{Namespace: testClusterNS, Name: "cleanup-" + appName}, job))
}
