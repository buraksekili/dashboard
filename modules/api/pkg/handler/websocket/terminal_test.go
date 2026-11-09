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
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	handlercommon "k8c.io/dashboard/v2/pkg/handler/common"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
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

func TestNewWebTerminalIdentity(t *testing.T) {
	testCases := []struct {
		name           string
		email          string
		groups         []string
		expectedUser   string
		expectedGroups []string
	}{
		{
			name:           "no groups",
			email:          testEmail,
			expectedUser:   testEmail,
			expectedGroups: []string{"system:authenticated"},
		},
		{
			name:           "groups are deduplicated and sorted",
			email:          "bob@acme.com",
			groups:         []string{"oidc:devs", "oidc:admins", "oidc:devs", ""},
			expectedUser:   "bob@acme.com",
			expectedGroups: []string{"oidc:admins", "oidc:devs", "system:authenticated"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			identity := newWebTerminalIdentity(tc.email, tc.groups)
			require.Equal(t, tc.expectedUser, identity.user)
			require.Equal(t, tc.expectedGroups, identity.groups)
		})
	}
}

func TestWebTerminalIdentityHash(t *testing.T) {
	base := newWebTerminalIdentity(testEmail, []string{"oidc:a", "oidc:b", "oidc:c"})

	testCases := []struct {
		name     string
		identity webTerminalIdentity
		same     bool
	}{
		{name: "permuted groups", identity: newWebTerminalIdentity(testEmail, []string{"oidc:c", "oidc:a", "oidc:b"}), same: true},
		{name: "unsorted groups", identity: webTerminalIdentity{user: testEmail, groups: []string{"system:authenticated", "oidc:c", "oidc:b", "oidc:a"}}, same: true},
		{name: "fewer groups", identity: newWebTerminalIdentity(testEmail, []string{"oidc:a", "oidc:b"})},
		{name: "other user", identity: newWebTerminalIdentity("alice@acme.com", []string{"oidc:a", "oidc:b", "oidc:c"})},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Len(t, tc.identity.hash(), 64)
			if tc.same {
				require.Equal(t, base.hash(), tc.identity.hash())
			} else {
				require.NotEqual(t, base.hash(), tc.identity.hash())
			}
		})
	}
}

func TestGenWebTerminalRBAC(t *testing.T) {
	userEmailID := EncodeUserEmailtoID(testEmail)
	appName := userAppName(userEmailID)
	identity := newWebTerminalIdentity(testEmail, []string{"oidc:devs", "oidc:admins"})

	sa := genWebTerminalServiceAccount(appName)
	require.Equal(t, "webterminal-"+userEmailID, sa.Name)
	require.Equal(t, metav1.NamespaceSystem, sa.Namespace)

	role := genWebTerminalClusterRole(userEmailID, identity)
	require.Equal(t, "kubermatic:webterminal:"+userEmailID, role.Name)
	require.Equal(t, []rbacv1.PolicyRule{
		{
			APIGroups:     []string{""},
			Resources:     []string{"users"},
			Verbs:         []string{"impersonate"},
			ResourceNames: []string{testEmail},
		},
		{
			APIGroups:     []string{""},
			Resources:     []string{"groups"},
			Verbs:         []string{"impersonate"},
			ResourceNames: []string{"oidc:admins", "oidc:devs", "system:authenticated"},
		},
	}, role.Rules)

	binding := genWebTerminalClusterRoleBinding(userEmailID, appName)
	require.Equal(t, role.Name, binding.Name)
	require.Equal(t, rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name}, binding.RoleRef)
	require.Equal(t, []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: appName, Namespace: metav1.NamespaceSystem}}, binding.Subjects)
}

func TestGenWebTerminalKubeconfigConfigMap(t *testing.T) {
	appName := userAppName(EncodeUserEmailtoID(testEmail))
	cluster := genTestCluster()
	cm, err := genWebTerminalKubeconfigConfigMap(appName, cluster)
	require.NoError(t, err)
	require.Equal(t, appName+"-kubeconfig", cm.Name)
	require.Equal(t, metav1.NamespaceSystem, cm.Namespace)

	// the shell talks to the proxy and has no credential at all
	shellCfg, err := clientcmd.Load([]byte(cm.Data[kubeconfigKey]))
	require.NoError(t, err)
	require.Equal(t, testClusterID, shellCfg.CurrentContext)
	require.Equal(t, "http://127.0.0.1:8001", shellCfg.Clusters[testClusterID].Server)
	authInfo := shellCfg.AuthInfos[shellCfg.Contexts[testClusterID].AuthInfo]
	require.NotNil(t, authInfo)
	require.Empty(t, authInfo.Token)
	require.Empty(t, authInfo.TokenFile)
	require.Nil(t, authInfo.AuthProvider)
	require.Nil(t, authInfo.Exec)
	require.Empty(t, authInfo.ClientCertificateData)

	// the proxy reads the projected token and applies the impersonation flags, which kubectl drops
	// with the in-cluster config
	proxyCfg, err := clientcmd.Load([]byte(cm.Data[proxyKubeconfigKey]))
	require.NoError(t, err)
	proxyCluster := proxyCfg.Clusters[proxyCfg.Contexts[proxyCfg.CurrentContext].Cluster]
	require.Equal(t, cluster.Status.Address.URL, proxyCluster.Server)
	require.Equal(t, "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", proxyCluster.CertificateAuthority)
	proxyUser := proxyCfg.AuthInfos[proxyCfg.Contexts[proxyCfg.CurrentContext].AuthInfo]
	require.Equal(t, "/var/run/secrets/kubernetes.io/serviceaccount/token", proxyUser.TokenFile)
	require.Empty(t, proxyUser.Token)

	// client-go reads the files while building the config, so point them to local files
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(caFile, []byte("ca"), 0o600))
	require.NoError(t, os.WriteFile(tokenFile, []byte("token"), 0o600))
	proxyCluster.CertificateAuthority = caFile
	proxyUser.TokenFile = tokenFile

	overrides := &clientcmd.ConfigOverrides{}
	overrides.AuthInfo.Impersonate = testEmail
	overrides.AuthInfo.ImpersonateGroups = []string{"oidc:devs", "system:authenticated"}
	restCfg, err := clientcmd.NewNonInteractiveClientConfig(*proxyCfg, "", overrides, nil).ClientConfig()
	require.NoError(t, err)
	require.Equal(t, cluster.Status.Address.URL, restCfg.Host)
	require.Equal(t, tokenFile, restCfg.BearerTokenFile)
	require.Equal(t, testEmail, restCfg.Impersonate.UserName)
	require.Equal(t, []string{"oidc:devs", "system:authenticated"}, restCfg.Impersonate.Groups)
}

func containerByName(t *testing.T, pod *corev1.Pod, name string) corev1.Container {
	t.Helper()
	for _, c := range pod.Spec.Containers {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("pod has no container %q", name)
	return corev1.Container{}
}

func TestGenWebTerminalPod(t *testing.T) {
	appName := userAppName(EncodeUserEmailtoID(testEmail))
	identity := newWebTerminalIdentity(testEmail, []string{"oidc:devs", "oidc:admins"})
	pod := genWebTerminalPod(appName, identity, nil, "")

	require.Equal(t, appName, pod.Spec.ServiceAccountName)
	require.NotNil(t, pod.Spec.AutomountServiceAccountToken)
	require.False(t, *pod.Spec.AutomountServiceAccountToken)
	require.Equal(t, identity.hash(), pod.Annotations[identityAnnotation])
	require.Equal(t, newWebTerminalIdentity(testEmail, []string{"oidc:admins", "oidc:devs"}).hash(), pod.Annotations[identityAnnotation])
	require.Equal(t, podSpecHash(pod.Spec), pod.Annotations[specHashAnnotation])
	require.Equal(t, pod.Annotations, genWebTerminalPod(appName, newWebTerminalIdentity(testEmail, []string{"oidc:admins", "oidc:devs"}), nil, "").Annotations)
	require.NotEqual(t, pod.Annotations[specHashAnnotation], genWebTerminalPod(appName, identity, nil, "registry.example.com").Annotations[specHashAnnotation])
	require.False(t, *pod.Spec.ShareProcessNamespace)
	require.Equal(t, int64(1), *pod.Spec.TerminationGracePeriodSeconds)

	volumes := map[string]corev1.Volume{}
	for _, v := range pod.Spec.Volumes {
		require.Nil(t, v.Secret, "volume %q must not mount a Secret", v.Name)
		volumes[v.Name] = v
	}

	shell := containerByName(t, pod, appName)
	for _, m := range shell.VolumeMounts {
		require.NotEqual(t, webTerminalServiceAccountVolume, m.Name)
		require.NotEqual(t, webTerminalProxyKubeconfigVolume, m.Name)
		require.False(t, strings.HasPrefix(m.MountPath, "/var/run/secrets"), "shell mounts %q", m.MountPath)
	}
	require.Contains(t, shell.Env, corev1.EnvVar{Name: "KUBECONFIG", Value: "/etc/kubernetes/kubeconfig/kubeconfig"})
	require.Contains(t, shell.VolumeMounts, corev1.VolumeMount{Name: webTerminalKubeconfigVolume, MountPath: "/etc/kubernetes/kubeconfig", ReadOnly: true})
	require.Equal(t, appName+"-kubeconfig", volumes[webTerminalKubeconfigVolume].ConfigMap.Name)
	require.Equal(t, []corev1.KeyToPath{{Key: kubeconfigKey, Path: "kubeconfig"}}, volumes[webTerminalKubeconfigVolume].ConfigMap.Items)

	proxy := containerByName(t, pod, proxyContainerName)
	require.Equal(t, []string{"kubectl"}, proxy.Command)
	require.Equal(t, []string{
		"proxy",
		"--address=127.0.0.1",
		"--port=8001",
		"--disable-filter=true",
		"--as=" + testEmail,
		"--as-group=oidc:admins",
		"--as-group=oidc:devs",
		"--as-group=system:authenticated",
	}, proxy.Args)
	require.Equal(t, &corev1.SecurityContext{
		AllowPrivilegeEscalation: ptr.To(false),
		RunAsUser:                ptr.To[int64](65534),
		RunAsGroup:               ptr.To[int64](65534),
		RunAsNonRoot:             ptr.To(true),
		ReadOnlyRootFilesystem:   ptr.To(true),
		Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}, proxy.SecurityContext)
	require.Contains(t, proxy.Env, corev1.EnvVar{Name: "HOME", Value: "/tmp"})
	require.Contains(t, proxy.VolumeMounts, corev1.VolumeMount{Name: proxyTmpDir, MountPath: "/tmp"})
	require.NotNil(t, volumes[proxyTmpDir].EmptyDir)
	require.False(t, proxy.Resources.Limits.Memory().IsZero())
	require.Contains(t, proxy.VolumeMounts, corev1.VolumeMount{Name: webTerminalServiceAccountVolume, MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true})
	require.Contains(t, proxy.Env, corev1.EnvVar{Name: "KUBECONFIG", Value: "/etc/kubernetes/proxy/kubeconfig"})
	require.Equal(t, []corev1.KeyToPath{{Key: proxyKubeconfigKey, Path: "kubeconfig"}}, volumes[webTerminalProxyKubeconfigVolume].ConfigMap.Items)

	projected := volumes[webTerminalServiceAccountVolume].Projected
	require.NotNil(t, projected)
	require.Len(t, projected.Sources, 3)
	require.Equal(t, int64(3600), *projected.Sources[0].ServiceAccountToken.ExpirationSeconds)
	require.Equal(t, "token", projected.Sources[0].ServiceAccountToken.Path)
	require.Equal(t, "kube-root-ca.crt", projected.Sources[1].ConfigMap.Name)
	require.Equal(t, []corev1.KeyToPath{{Key: "ca.crt", Path: "ca.crt"}}, projected.Sources[1].ConfigMap.Items)
	require.Equal(t, "namespace", projected.Sources[2].DownwardAPI.Items[0].Path)
	require.Equal(t, "metadata.namespace", projected.Sources[2].DownwardAPI.Items[0].FieldRef.FieldPath)
}

func TestGenWebTerminalCleanupJob(t *testing.T) {
	userEmailID := EncodeUserEmailtoID(testEmail)
	job := genWebTerminalCleanupJob(userAppName(userEmailID), userEmailID, testClusterNS, "")
	require.Equal(t, testClusterNS, job.Namespace)
	require.True(t, isCurrentCleanupJob(job))

	container := job.Spec.Template.Spec.Containers[0]
	env := map[string]string{}
	for _, e := range container.Env {
		env[e.Name] = e.Value
	}
	require.Equal(t, handlercommon.KubeconfigSecretName(userEmailID), env["KUBECONFIG_SECRET_NAME"])
	require.Equal(t, "kubermatic:webterminal:"+userEmailID, env["WEBTERMINAL_RBAC_NAME"])
	require.Equal(t, "webterminal-"+userEmailID, env["USER_APP_NAME"])

	script := strings.Join(container.Args, "\n")
	for _, cmd := range []string{
		"kubectl delete clusterrolebinding $WEBTERMINAL_RBAC_NAME --ignore-not-found || rc=1",
		"kubectl delete clusterrole $WEBTERMINAL_RBAC_NAME --ignore-not-found || rc=1",
		"kubectl delete pod $USER_APP_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1",
		"kubectl delete serviceaccount $USER_APP_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1",
		"kubectl delete configmap $USER_APP_NAME-kubeconfig -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1",
		"kubectl delete secret $KUBECONFIG_SECRET_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1",
		"kubectl delete networkpolicy $USER_APP_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1",
		"kubectl delete configmap $USER_APP_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1",
		"exit $rc",
	} {
		require.Contains(t, script, cmd)
	}
}

// genTestClusterWithStrategy returns a cluster whose address matches what the KKP address
// reconciler writes: the URL uses the external name and the port, the IP is the external name resolved.
func genTestClusterWithStrategy(strategy kubermaticv1.ExposeStrategy, port int32) *kubermaticv1.Cluster {
	cluster := &kubermaticv1.Cluster{ObjectMeta: metav1.ObjectMeta{Name: testClusterID}}
	cluster.Spec.ExposeStrategy = strategy
	cluster.Spec.Cloud.DatacenterName = "dc1"
	cluster.Status.NamespaceName = testClusterNS
	cluster.Status.Address.ExternalName = testClusterID + ".seed.example.com"
	cluster.Status.Address.IP = "10.0.0.1"
	cluster.Status.Address.Port = port
	cluster.Status.Address.URL = "https://" + net.JoinHostPort(cluster.Status.Address.ExternalName, fmt.Sprint(port))
	cluster.Spec.ClusterNetwork.Services.CIDRBlocks = []string{"10.240.16.0/20"}
	return cluster
}

func genTestCluster() *kubermaticv1.Cluster {
	return genTestClusterWithStrategy(kubermaticv1.ExposeStrategyNodePort, 30443)
}

// genOldModelPod returns a pod as created by the token based web terminal.
func genOldModelPod(appName, userEmailID string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: appName, Namespace: metav1.NamespaceSystem, UID: "uid-existing"},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{
				Name:         "web-terminal-kubeconfig",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: handlercommon.KubeconfigSecretName(userEmailID)}},
			}},
			Containers: []corev1.Container{{Name: appName, Image: "web-terminal"}},
		},
	}
}

func TestPrepareResources(t *testing.T) {
	userEmailID := EncodeUserEmailtoID(testEmail)
	appName := userAppName(userEmailID)
	identity := newWebTerminalIdentity(testEmail, []string{"oidc:devs"})
	podKey := types.NamespacedName{Namespace: metav1.NamespaceSystem, Name: appName}

	currentPod := func(id webTerminalIdentity) *corev1.Pod {
		pod := genWebTerminalPod(appName, id, nil, "")
		pod.UID = "uid-existing"
		return pod
	}

	testCases := []struct {
		name            string
		clusterObjects  []ctrlruntimeclient.Object
		seedObjects     []ctrlruntimeclient.Object
		expectPodReused bool
	}{
		{
			name: "fresh start",
		},
		{
			name:            "pod with the same identity is reused",
			clusterObjects:  []ctrlruntimeclient.Object{currentPod(newWebTerminalIdentity(testEmail, []string{"oidc:devs"}))},
			expectPodReused: true,
		},
		{
			name:           "pod with another identity is recreated",
			clusterObjects: []ctrlruntimeclient.Object{currentPod(newWebTerminalIdentity(testEmail, []string{"oidc:devs", "oidc:admins"}))},
		},
		{
			name: "pod from an older spec is recreated",
			clusterObjects: []ctrlruntimeclient.Object{func() *corev1.Pod {
				pod := currentPod(identity)
				pod.Annotations[specHashAnnotation] = "old"
				return pod
			}()},
		},
		{
			name: "failed pod is recreated",
			clusterObjects: []ctrlruntimeclient.Object{func() *corev1.Pod {
				pod := currentPod(identity)
				pod.Status.Phase = corev1.PodFailed
				return pod
			}()},
		},
		{
			name: "succeeded pod is recreated",
			clusterObjects: []ctrlruntimeclient.Object{func() *corev1.Pod {
				pod := currentPod(identity)
				pod.Status.Phase = corev1.PodSucceeded
				return pod
			}()},
		},
		{
			name:           "pod without the proxy is recreated",
			clusterObjects: []ctrlruntimeclient.Object{genOldModelPod(appName, userEmailID)},
		},
		{
			name: "old model resources are deleted and RBAC is updated",
			clusterObjects: []ctrlruntimeclient.Object{
				genOldModelPod(appName, userEmailID),
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: metav1.NamespaceSystem, Name: handlercommon.KubeconfigSecretName(userEmailID)}},
				genWebTerminalClusterRole(userEmailID, newWebTerminalIdentity(testEmail, []string{"oidc:old"})),
			},
			seedObjects: []ctrlruntimeclient.Object{
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: testClusterNS, Name: handlercommon.WebTerminalOIDCSecretName(userEmailID)}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			podDeletes := 0
			clusterClient := ctrlruntimefake.NewClientBuilder().WithObjects(tc.clusterObjects...).WithInterceptorFuncs(interceptor.Funcs{
				Delete: func(ctx context.Context, c ctrlruntimeclient.WithWatch, obj ctrlruntimeclient.Object, opts ...ctrlruntimeclient.DeleteOption) error {
					if _, ok := obj.(*corev1.Pod); ok {
						podDeletes++
					}
					return c.Delete(ctx, obj, opts...)
				},
			}).Build()
			seedClient := ctrlruntimefake.NewClientBuilder().WithObjects(tc.seedObjects...).Build()

			desired, err := prepareResources(ctx, clusterClient, seedClient, identity, userEmailID, appName, genTestCluster(), nil, "")
			require.NoError(t, err)

			pod := &corev1.Pod{}
			require.NoError(t, clusterClient.Get(ctx, podKey, pod))
			require.Equal(t, identity.hash(), pod.Annotations[identityAnnotation])
			require.True(t, podMatches(pod, desired))
			containerByName(t, pod, proxyContainerName)
			if tc.expectPodReused {
				require.Equal(t, 0, podDeletes)
				require.Equal(t, types.UID("uid-existing"), pod.UID)
			} else if len(tc.clusterObjects) > 0 {
				require.Equal(t, 1, podDeletes, "the old pod must be deleted before it is recreated")
			}

			require.NoError(t, clusterClient.Get(ctx, podKey, &corev1.ServiceAccount{}))
			require.NoError(t, clusterClient.Get(ctx, podKey, &networkingv1.NetworkPolicy{}))
			require.NoError(t, clusterClient.Get(ctx, podKey, &corev1.ConfigMap{}))
			require.NoError(t, clusterClient.Get(ctx, types.NamespacedName{Namespace: metav1.NamespaceSystem, Name: appName + "-kubeconfig"}, &corev1.ConfigMap{}))

			role := &rbacv1.ClusterRole{}
			require.NoError(t, clusterClient.Get(ctx, types.NamespacedName{Name: webTerminalRBACName(userEmailID)}, role))
			require.Equal(t, genWebTerminalClusterRole(userEmailID, identity).Rules, role.Rules)
			require.NoError(t, clusterClient.Get(ctx, types.NamespacedName{Name: webTerminalRBACName(userEmailID)}, &rbacv1.ClusterRoleBinding{}))

			err = clusterClient.Get(ctx, types.NamespacedName{Namespace: metav1.NamespaceSystem, Name: handlercommon.KubeconfigSecretName(userEmailID)}, &corev1.Secret{})
			require.True(t, apierrors.IsNotFound(err), "expected the legacy kubeconfig secret to be gone, got %v", err)
			err = seedClient.Get(ctx, types.NamespacedName{Namespace: testClusterNS, Name: handlercommon.WebTerminalOIDCSecretName(userEmailID)}, &corev1.Secret{})
			require.True(t, apierrors.IsNotFound(err), "expected the seed refresh token secret to be gone, got %v", err)

			job := &batchv1.Job{}
			require.NoError(t, seedClient.Get(ctx, types.NamespacedName{Namespace: testClusterNS, Name: "cleanup-" + appName}, job))
			require.True(t, isCurrentCleanupJob(job))
		})
	}
}

func TestPrepareResourcesReplacesLegacyJob(t *testing.T) {
	ctx := context.Background()
	userEmailID := EncodeUserEmailtoID(testEmail)
	appName := userAppName(userEmailID)

	// a job created by an older version, its script does not delete the RBAC resources
	legacyJob := genWebTerminalCleanupJob(appName, userEmailID, testClusterNS, "")
	legacyJob.UID = "uid-legacy"
	container := &legacyJob.Spec.Template.Spec.Containers[0]
	env := []corev1.EnvVar{}
	for _, e := range container.Env {
		if e.Name != "WEBTERMINAL_RBAC_NAME" {
			env = append(env, e)
		}
	}
	container.Env = env
	require.False(t, isCurrentCleanupJob(legacyJob))

	seedClient := ctrlruntimefake.NewClientBuilder().WithObjects(legacyJob).Build()
	identity := newWebTerminalIdentity(testEmail, nil)
	_, err := prepareResources(ctx, ctrlruntimefake.NewClientBuilder().Build(), seedClient, identity, userEmailID, appName, genTestCluster(), nil, "")
	require.NoError(t, err)

	job := &batchv1.Job{}
	require.NoError(t, seedClient.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(legacyJob), job))
	require.NotEqual(t, types.UID("uid-legacy"), job.UID)
	require.True(t, isCurrentCleanupJob(job))
}

func TestPrepareResourcesKeepsCurrentJob(t *testing.T) {
	ctx := context.Background()
	userEmailID := EncodeUserEmailtoID(testEmail)
	appName := userAppName(userEmailID)

	currentJob := genWebTerminalCleanupJob(appName, userEmailID, testClusterNS, "")
	currentJob.UID = "uid-current"
	seedClient := ctrlruntimefake.NewClientBuilder().WithObjects(currentJob).Build()

	_, err := prepareResources(ctx, ctrlruntimefake.NewClientBuilder().Build(), seedClient, newWebTerminalIdentity(testEmail, nil), userEmailID, appName, genTestCluster(), nil, "")
	require.NoError(t, err)

	job := &batchv1.Job{}
	require.NoError(t, seedClient.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(currentJob), job))
	require.Equal(t, types.UID("uid-current"), job.UID)
}

// The proxy must reach the API server under the address the NetworkPolicy allows, for every expose strategy.
func TestNetworkPolicyAllowsProxyDestination(t *testing.T) {
	testCases := []struct {
		strategy kubermaticv1.ExposeStrategy
		port     int32
	}{
		{strategy: kubermaticv1.ExposeStrategyNodePort, port: 30443},
		{strategy: kubermaticv1.ExposeStrategyLoadBalancer, port: 31443},
		// with Tunneling the port is the target port of the apiserver Service
		{strategy: kubermaticv1.ExposeStrategyTunneling, port: 6443},
	}

	for _, tc := range testCases {
		t.Run(string(tc.strategy), func(t *testing.T) {
			cluster := genTestClusterWithStrategy(tc.strategy, tc.port)
			appName := userAppName(EncodeUserEmailtoID(testEmail))

			cm, err := genWebTerminalKubeconfigConfigMap(appName, cluster)
			require.NoError(t, err)
			proxyCfg, err := clientcmd.Load([]byte(cm.Data[proxyKubeconfigKey]))
			require.NoError(t, err)
			server, err := url.Parse(proxyCfg.Clusters[proxyCfg.Contexts[proxyCfg.CurrentContext].Cluster].Server)
			require.NoError(t, err)

			// the server is the external name, which resolves to Status.Address.IP
			require.Equal(t, cluster.Status.Address.ExternalName, server.Hostname())
			require.Equal(t, fmt.Sprint(tc.port), server.Port())

			np, err := genWebTerminalNetworkPolicy(appName, cluster, nil)
			require.NoError(t, err)
			allowed := false
			for _, rule := range np.Spec.Egress {
				for _, peer := range rule.To {
					if peer.IPBlock == nil || peer.IPBlock.CIDR != cluster.Status.Address.IP+"/32" {
						continue
					}
					for _, port := range rule.Ports {
						if port.Port != nil && port.Port.String() == server.Port() && *port.Protocol == corev1.ProtocolTCP {
							allowed = true
						}
					}
				}
			}
			require.True(t, allowed, "the NetworkPolicy does not allow %s:%s", cluster.Status.Address.IP, server.Port())
		})
	}
}

func TestGenWebTerminalKubeconfigConfigMapWithoutURL(t *testing.T) {
	cluster := genTestCluster()
	cluster.Status.Address.URL = ""
	_, err := genWebTerminalKubeconfigConfigMap("webterminal-x", cluster)
	require.Error(t, err)
}

// The ClusterRole must only allow impersonating the exact user and groups.
func TestGenWebTerminalClusterRoleShape(t *testing.T) {
	identity := newWebTerminalIdentity(testEmail, []string{"oidc:devs", "oidc:admins"})
	role := genWebTerminalClusterRole(EncodeUserEmailtoID(testEmail), identity)

	require.Len(t, role.Rules, 2)
	seen := map[string][]string{}
	for _, rule := range role.Rules {
		require.Equal(t, []string{""}, rule.APIGroups)
		require.Equal(t, []string{"impersonate"}, rule.Verbs)
		require.Empty(t, rule.NonResourceURLs)
		require.Len(t, rule.Resources, 1)
		require.NotEmpty(t, rule.ResourceNames)
		for _, field := range [][]string{rule.APIGroups, rule.Verbs, rule.Resources, rule.ResourceNames} {
			for _, v := range field {
				require.NotContains(t, v, "*")
			}
		}
		seen[rule.Resources[0]] = rule.ResourceNames
	}
	require.Equal(t, map[string][]string{
		"users":  {testEmail},
		"groups": {"oidc:admins", "oidc:devs", "system:authenticated"},
	}, seen)
	require.Nil(t, role.AggregationRule)
}

func TestPrepareResourcesRequiresNamespace(t *testing.T) {
	cluster := genTestCluster()
	cluster.Status.NamespaceName = ""
	userEmailID := EncodeUserEmailtoID(testEmail)
	seedClient := ctrlruntimefake.NewClientBuilder().Build()

	_, err := prepareResources(context.Background(), ctrlruntimefake.NewClientBuilder().Build(), seedClient, newWebTerminalIdentity(testEmail, nil), userEmailID, userAppName(userEmailID), cluster, nil, "")
	require.Error(t, err)

	jobs := &batchv1.JobList{}
	require.NoError(t, seedClient.List(context.Background(), jobs))
	require.Empty(t, jobs.Items)
}

// A parallel session recreates the pod while this one waits for its deletion.
func TestEnsurePodParallelRecreate(t *testing.T) {
	ctx := context.Background()
	appName := userAppName(EncodeUserEmailtoID(testEmail))
	identity := newWebTerminalIdentity(testEmail, nil)
	desired := genWebTerminalPod(appName, identity, nil, "")

	old := genWebTerminalPod(appName, newWebTerminalIdentity(testEmail, []string{"oidc:old"}), nil, "")
	old.UID = "uid-old"

	podDeletes := 0
	clusterClient := ctrlruntimefake.NewClientBuilder().WithObjects(old).WithInterceptorFuncs(interceptor.Funcs{
		Delete: func(ctx context.Context, c ctrlruntimeclient.WithWatch, obj ctrlruntimeclient.Object, opts ...ctrlruntimeclient.DeleteOption) error {
			podDeletes++
			if err := c.Delete(ctx, obj, opts...); err != nil {
				return err
			}
			// the other session creates its pod right after our delete
			other := desired.DeepCopy()
			other.UID = "uid-other"
			return c.Create(ctx, other)
		},
	}).Build()

	require.NoError(t, ensurePod(ctx, clusterClient, desired.DeepCopy()))
	require.Equal(t, 1, podDeletes)

	pod := &corev1.Pod{}
	require.NoError(t, clusterClient.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(desired), pod))
	require.Equal(t, types.UID("uid-other"), pod.UID)
	require.True(t, podMatches(pod, desired))
}

// A parallel session replaces the legacy job while this one waits for its deletion.
func TestEnsureCleanupJobParallelRecreate(t *testing.T) {
	ctx := context.Background()
	userEmailID := EncodeUserEmailtoID(testEmail)
	appName := userAppName(userEmailID)

	legacyJob := genWebTerminalCleanupJob(appName, userEmailID, testClusterNS, "")
	legacyJob.UID = "uid-legacy"
	legacyJob.Spec.Template.Spec.Containers[0].Env = nil

	seedClient := ctrlruntimefake.NewClientBuilder().WithObjects(legacyJob).WithInterceptorFuncs(interceptor.Funcs{
		Delete: func(ctx context.Context, c ctrlruntimeclient.WithWatch, obj ctrlruntimeclient.Object, opts ...ctrlruntimeclient.DeleteOption) error {
			if err := c.Delete(ctx, obj, opts...); err != nil {
				return err
			}
			other := genWebTerminalCleanupJob(appName, userEmailID, testClusterNS, "")
			other.UID = "uid-other"
			return c.Create(ctx, other)
		},
	}).Build()

	require.NoError(t, ensureCleanupJob(ctx, seedClient, userEmailID, appName, testClusterNS, ""))

	job := &batchv1.Job{}
	require.NoError(t, seedClient.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(legacyJob), job))
	require.Equal(t, types.UID("uid-other"), job.UID)
	require.True(t, isCurrentCleanupJob(job))
}

func TestPodMatches(t *testing.T) {
	appName := userAppName(EncodeUserEmailtoID(testEmail))
	desired := genWebTerminalPod(appName, newWebTerminalIdentity(testEmail, []string{"oidc:devs"}), nil, "")

	require.True(t, podMatches(genWebTerminalPod(appName, newWebTerminalIdentity(testEmail, []string{"oidc:devs"}), nil, ""), desired))
	require.False(t, podMatches(genWebTerminalPod(appName, newWebTerminalIdentity("alice@acme.com", []string{"oidc:devs"}), nil, ""), desired))
	require.False(t, podMatches(genWebTerminalPod(appName, newWebTerminalIdentity(testEmail, nil), nil, ""), desired))
	require.False(t, podMatches(&corev1.Pod{}, desired))
}
