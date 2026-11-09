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

package websocket

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/gorilla/websocket"

	handlercommon "k8c.io/dashboard/v2/pkg/handler/common"
	authtypes "k8c.io/dashboard/v2/pkg/provider/auth/types"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/log"
	"k8c.io/kubermatic/v2/pkg/resources"
	"k8c.io/kubermatic/v2/pkg/resources/registry"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/util/retry"
	"k8s.io/kubectl/pkg/scheme"
	"k8s.io/utils/ptr"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	END_OF_TRANSMISSION               = "\u0004"
	timeout                           = 2 * time.Minute
	appName                           = "webterminal"
	webTerminalStorage                = "web-terminal-storage"
	webTerminalConfigVolume           = "web-terminal-config"
	podLifetime                       = 30 * time.Minute
	maxNumberOfExpirationRefreshes    = 48              // it means maximum 24h for a pod lifetime of 30 minutes
	remainingExpirationTimeForWarning = 5 * time.Minute // should be lesser than "podLifetime"
	expirationCheckInterval           = 1 * time.Minute // should be lesser than "remainingExpirationTimeForWarning"
	expirationTimestampKey            = "ExpirationTimestamp"
	expirationRefreshesKey            = "ExpirationRefreshes"
	pingInterval                      = 30 * time.Second
	pingMessage                       = "PING"
	pongMessage                       = "PONG"

	// env vars of the cleanup Job. Jobs created by older versions lack rbacNameEnv and get replaced.
	kubeconfigSecretNameEnv = "KUBECONFIG_SECRET_NAME"
	rbacNameEnv             = "WEBTERMINAL_RBAC_NAME"

	webTerminalImage                   = resources.WEBTerminalImage
	webTerminalContainerKubeconfigPath = "/etc/kubernetes/kubeconfig/kubeconfig"

	webTerminalCABundleVolume = "ca-bundle"
	webTerminalCABundleDir    = "/etc/kubermatic/certs"
	webTerminalCABundlePath   = webTerminalCABundleDir + "/" + resources.CABundleConfigMapKey

	webTerminalKubeconfigVolume      = "web-terminal-kubeconfig"
	webTerminalProxyKubeconfigVolume = "web-terminal-proxy-kubeconfig"
	webTerminalServiceAccountVolume  = "web-terminal-serviceaccount"
	kubeconfigKey                    = "kubeconfig"
	proxyKubeconfigKey               = "proxy-kubeconfig"
	proxyKubeconfigDir               = "/etc/kubernetes/proxy"
	serviceAccountDir                = "/var/run/secrets/kubernetes.io/serviceaccount"
	serviceAccountTokenExpiration    = 3600

	proxyContainerName = "proxy"
	proxyAddress       = "127.0.0.1"
	proxyPort          = 8001

	identityAnnotation       = "webterminal.kubermatic.k8c.io/identity"
	specHashAnnotation       = "webterminal.kubermatic.k8c.io/spec-hash"
	podDeletionTimeout       = 2 * time.Minute
	podDeletionCheckInterval = time.Second
	// the shell ignores SIGTERM, so a long grace period only delays the replacement of the pod.
	podTerminationGracePeriod = 1

	proxyUser    = 65534
	proxyHomeDir = "/tmp"
	proxyTmpDir  = "web-terminal-proxy-tmp"
)

type TerminalConnStatus string

const (
	WebterminalPodPending  TerminalConnStatus = "WEBTERMINAL_POD_PENDING"
	WebterminalPodFailed   TerminalConnStatus = "WEBTERMINAL_POD_FAILED"
	ConnectionPoolExceeded TerminalConnStatus = "CONNECTION_POOL_EXCEEDED"
	RefreshesLimitExceeded TerminalConnStatus = "REFRESHES_LIMIT_EXCEEDED"
	// WebTerminalIdentityUnsupported is sent when the user cluster maps OIDC claims in a way the
	// web terminal cannot reproduce, e.g. with a custom AuthenticationConfiguration.
	WebTerminalIdentityUnsupported TerminalConnStatus = "WEBTERMINAL_IDENTITY_UNSUPPORTED"
	// WebTerminalIdentityRejected is sent when the token of the user gives no identity the web
	// terminal may impersonate, e.g. an unverified email or a reserved "system:" name.
	WebTerminalIdentityRejected TerminalConnStatus = "WEBTERMINAL_IDENTITY_REJECTED"
)

// PtyHandler is what remote command expects from a pty.
type PtyHandler interface {
	io.Reader
	io.Writer
	remotecommand.TerminalSizeQueue
}

// TerminalSession implements PtyHandler (using a websocket connection).
type TerminalSession struct {
	websocketConn *websocket.Conn
	sizeChan      chan remotecommand.TerminalSize
	doneChan      chan struct{}

	userEmailID   string
	clusterClient ctrlruntimeclient.Client
}

// TerminalMessage is the messaging protocol between ShellController and TerminalSession.
//
// OP          DIRECTION  FIELD(S) USED  DESCRIPTION
// ---------------------------------------------------------------------
// stdin       fe->be     Data           Keystrokes/paste buffer.
// resize      fe->be     Rows, Cols     New terminal size.
// refresh     fe->be                    Signal to extend expiration time.
// msg         fe->be     Data           Any other necessary message from the frontend to the backend.
// stdout      be->fe     Data           Output from the process.
// toast       be->fe     Data           OOB message to be shown to the user.
// msg         be->fe     Data           Any necessary message from the backend to the frontend.
// expiration  be->fe     Data           Expiration timestamp in seconds.
type TerminalMessage struct {
	Op, Data   string
	Rows, Cols uint16
}

// TerminalSize handles pty->process resize events.
// Called in a loop from remotecommand as long as the process is running.
func (t TerminalSession) Next() *remotecommand.TerminalSize {
	select {
	case size := <-t.sizeChan:
		return &size
	case <-t.doneChan:
		return nil
	}
}

// Read handles pty->process messages (stdin, resize, refresh, msg).
// Called in a loop from remotecommand as long as the process is running.
func (t TerminalSession) Read(p []byte) (int, error) {
	_, m, err := t.websocketConn.ReadMessage()
	if err != nil {
		// Send terminated signal to process to avoid resource leak
		return copy(p, END_OF_TRANSMISSION), err
	}

	var msg TerminalMessage
	if err := json.Unmarshal(m, &msg); err != nil {
		return copy(p, END_OF_TRANSMISSION), err
	}

	switch msg.Op {
	case "stdin":
		return copy(p, msg.Data), nil
	case "resize":
		t.sizeChan <- remotecommand.TerminalSize{Width: msg.Cols, Height: msg.Rows}
		return 0, nil
	case "refresh":
		return 0, t.extendExpirationTime(context.Background())
	case "msg":
		switch msg.Data {
		case pongMessage:
			// just ignore "pong" messages
			return 0, nil
		default:
			return 0, fmt.Errorf("unexpected message '%s'", msg.Data)
		}
	default:
		return copy(p, END_OF_TRANSMISSION), fmt.Errorf("unknown message type '%s'", msg.Op)
	}
}

// Write handles process->pty stdout.
// Called from remotecommand whenever there is any output.
func (t TerminalSession) Write(p []byte) (int, error) {
	msg, err := json.Marshal(TerminalMessage{
		Op:   "stdout",
		Data: string(p),
	})
	if err != nil {
		return 0, err
	}

	if err = t.websocketConn.WriteMessage(websocket.TextMessage, msg); err != nil {
		return 0, err
	}

	return len(p), nil
}

// Toast can be used to send the user any OOB messages.
// hterm puts these in the center of the terminal.
func (t TerminalSession) Toast(p string) error {
	msg, err := json.Marshal(TerminalMessage{
		Op:   "toast",
		Data: p,
	})
	if err != nil {
		return err
	}

	if err = t.websocketConn.WriteMessage(websocket.TextMessage, msg); err != nil {
		return err
	}
	return nil
}

func (t TerminalSession) extendExpirationTime(ctx context.Context) error {
	_, currentNumberOfRefreshes, err := getWebTerminalExpirationValues(ctx, t.clusterClient, t.userEmailID)
	if err != nil {
		return err
	}

	if currentNumberOfRefreshes >= maxNumberOfExpirationRefreshes {
		_ = SendMessage(t.websocketConn, string(RefreshesLimitExceeded))
		return nil
	}

	// regenerate the configmap to extend the expiration period
	if err := t.clusterClient.Update(ctx,
		genWebTerminalConfigMap(
			userAppName(t.userEmailID),
			currentNumberOfRefreshes+1,
		)); err != nil {
		return err
	}

	return nil
}

func userAppName(userEmailID string) string {
	return fmt.Sprintf("%s-%s", appName, userEmailID)
}

func getWebTerminalExpirationValues(ctx context.Context, clusterClient ctrlruntimeclient.Client, userEmailID string) (time.Time, int, error) {
	webTerminalConfigMap := &corev1.ConfigMap{}
	if err := clusterClient.Get(ctx, ctrlruntimeclient.ObjectKey{
		Namespace: metav1.NamespaceSystem,
		Name:      userAppName(userEmailID),
	}, webTerminalConfigMap); err != nil {
		return time.Time{}, 0, err
	}

	if webTerminalConfigMap.Data == nil {
		return time.Time{}, 0, errors.New("no data set for webterminal configmap")
	}

	expirationTimestampStr, isExpirationSet := webTerminalConfigMap.Data[expirationTimestampKey]
	if !isExpirationSet {
		return time.Time{}, 0, errors.New("no expiration set in the webterminal configmap")
	}
	expirationTimestamp, err := strconv.ParseInt(expirationTimestampStr, 10, 64)
	if err != nil {
		return time.Time{}, 0, errors.New("invalid expiration timestamp in the webterminal configmap")
	}
	expirationTime := time.Unix(expirationTimestamp, 0)

	expirationRefreshesStr, isExpirationRefreshesSet := webTerminalConfigMap.Data[expirationRefreshesKey]
	if !isExpirationRefreshesSet {
		return time.Time{}, 0, errors.New("no number of expiration refreshes set in the webterminal configmap")
	}
	expirationRefreshes, err := strconv.Atoi(expirationRefreshesStr)
	if err != nil {
		return time.Time{}, 0, errors.New("invalid number of expiration refreshes in the webterminal configmap")
	}

	return expirationTime, expirationRefreshes, nil
}

func pingRoutine(ctx context.Context, websocketConn *websocket.Conn) {
	for {
		if !sleepCtx(ctx, pingInterval) {
			return
		}
		// Message to check if connection with client is active.
		if err := SendMessage(websocketConn, pingMessage); err != nil {
			// connection is already closed, so just return
			return
		}
	}
}

// jsonWriter is the part of the websocket connection used to send status messages.
type jsonWriter interface {
	WriteJSON(v interface{}) error
}

// sleepCtx waits for d and returns false if ctx is done first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

func expirationCheckRoutine(ctx context.Context, clusterClient ctrlruntimeclient.Client, userEmailID string, websocketConn *websocket.Conn) {
	for {
		if !sleepCtx(ctx, expirationCheckInterval) {
			return
		}

		expirationTime, numberOfRefreshes, err := getWebTerminalExpirationValues(ctx, clusterClient, userEmailID)
		if err != nil {
			log.Logger.Debug(err)
			break
		}

		remainingExpirationTime := time.Until(expirationTime)

		if remainingExpirationTime <= 0 || numberOfRefreshes > maxNumberOfExpirationRefreshes {
			// web terminal is already expired, so break the check loop
			break
		}

		if remainingExpirationTime < remainingExpirationTimeForWarning {
			_ = websocketConn.WriteJSON(TerminalMessage{
				Op:   "expiration",
				Data: expirationTime.UTC().Format(time.RFC3339),
			})
		}
	}
}

func webTerminalRBACName(userEmailID string) string {
	return fmt.Sprintf("kubermatic:%s:%s", appName, userEmailID)
}

func webTerminalKubeconfigConfigMapName(userAppName string) string {
	return userAppName + "-kubeconfig"
}

// startProcess is called by terminal session creation.
// Executed cmd in the container specified in request and connects it up with the ptyHandler (a session).
func startProcess(ctx context.Context, client, seedClient ctrlruntimeclient.Client, k8sClient kubernetes.Interface, cfg *rest.Config, identity webTerminalIdentity, userEmailID string, cluster *kubermaticv1.Cluster, options *kubermaticv1.WebTerminalOptions, overwriteRegistry string, cmd []string, ptyHandler PtyHandler, websocketConn *websocket.Conn) error {
	userAppName := userAppName(userEmailID)
	desiredPod, err := prepareResources(ctx, client, seedClient, identity, userEmailID, userAppName, cluster, options, overwriteRegistry)
	if err != nil {
		return err
	}

	var foreignPod bool
	if !WaitFor(ctx, 5*time.Second, timeout, func(ctx context.Context) bool {
		pod := &corev1.Pod{}
		if err := client.Get(ctx, ctrlruntimeclient.ObjectKey{
			Namespace: metav1.NamespaceSystem,
			Name:      userAppName,
		}, pod); err != nil {
			return false
		}

		// a parallel session can replace the pod, never exec into a pod made for another identity
		if !podMatches(pod, desiredPod) {
			foreignPod = true
			return true
		}

		var status string

		switch pod.Status.Phase {
		case corev1.PodRunning:
			return true
		case corev1.PodPending:
			status = string(WebterminalPodPending)
		case corev1.PodFailed:
			status = string(WebterminalPodFailed)
		default:
			status = fmt.Sprintf("pod in %s phase", pod.Status.Phase)
		}
		_ = SendMessage(websocketConn, status)
		return false
	}) {
		return fmt.Errorf("the WEB terminal Pod is not ready")
	}
	if foreignPod {
		return fmt.Errorf("the WEB terminal Pod %s was replaced for another identity", userAppName)
	}

	go pingRoutine(ctx, websocketConn)

	go expirationCheckRoutine(ctx, client, userEmailID, websocketConn)

	req := k8sClient.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(userAppName).
		Namespace(metav1.NamespaceSystem).
		SubResource("exec")

	req.VersionedParams(&corev1.PodExecOptions{
		Container: userAppName,
		Command:   cmd,
		Stdin:     true,
		Stdout:    true,
		Stderr:    true,
		TTY:       true,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(cfg, http.MethodPost, req.URL())
	if err != nil {
		return err
	}

	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:             ptyHandler,
		Stdout:            ptyHandler,
		Stderr:            ptyHandler,
		TerminalSizeQueue: ptyHandler,
		Tty:               true,
	})
	if err != nil {
		return err
	}

	return nil
}

// prepareResources creates or updates the user cluster resources of the web terminal, removes the
// resources of the older token based model and makes sure the cleanup Job exists. It returns the
// pod the session must exec into.
func prepareResources(ctx context.Context, client, seedClient ctrlruntimeclient.Client, identity webTerminalIdentity, userEmailID, userAppName string, cluster *kubermaticv1.Cluster, options *kubermaticv1.WebTerminalOptions, overwriteRegistry string) (*corev1.Pod, error) {
	if cluster.Status.NamespaceName == "" {
		return nil, fmt.Errorf("cluster %s has no namespace yet", cluster.Name)
	}

	// the old model kept an OIDC kubeconfig in the user cluster and the refresh token in the seed
	if err := deleteIgnoreNotFound(ctx, client, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: metav1.NamespaceSystem,
		Name:      handlercommon.KubeconfigSecretName(userEmailID),
	}}); err != nil {
		return nil, err
	}
	if err := deleteIgnoreNotFound(ctx, seedClient, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Namespace: cluster.Status.NamespaceName,
		Name:      handlercommon.WebTerminalOIDCSecretName(userEmailID),
	}}); err != nil {
		return nil, err
	}

	// renew the expiration time before the cleanup Job can read it
	if err := createOrUpdate(ctx, client, genWebTerminalConfigMap(userAppName, 0)); err != nil {
		return nil, err
	}

	if err := ensureCleanupJob(ctx, seedClient, userEmailID, userAppName, cluster.Status.NamespaceName, overwriteRegistry); err != nil {
		return nil, err
	}

	webTerminalNetworkPolicy, err := genWebTerminalNetworkPolicy(userAppName, cluster, options)
	if err != nil {
		return nil, err
	}
	kubeconfigConfigMap, err := genWebTerminalKubeconfigConfigMap(userAppName, cluster)
	if err != nil {
		return nil, err
	}

	for _, obj := range []ctrlruntimeclient.Object{
		webTerminalNetworkPolicy,
		genWebTerminalServiceAccount(userAppName),
		genWebTerminalClusterRole(userEmailID, identity),
		genWebTerminalClusterRoleBinding(userEmailID, userAppName),
		kubeconfigConfigMap,
	} {
		if err := createOrUpdate(ctx, client, obj); err != nil {
			return nil, err
		}
	}

	pod := genWebTerminalPod(userAppName, identity, options, overwriteRegistry)
	if err := ensurePod(ctx, client, pod); err != nil {
		return nil, err
	}
	return pod, nil
}

// ensurePod creates the web terminal pod. An existing pod is kept only when it was created from the
// same spec for the same identity and is still usable, otherwise it is deleted and created again.
func ensurePod(ctx context.Context, client ctrlruntimeclient.Client, pod *corev1.Pod) error {
	key := ctrlruntimeclient.ObjectKeyFromObject(pod)

	existing := &corev1.Pod{}
	err := client.Get(ctx, key, existing)
	switch {
	case apierrors.IsNotFound(err):
	case err != nil:
		return err
	case !podNeedsReplacement(existing, pod):
		return nil
	default:
		if err := deleteIgnoreNotFound(ctx, client, existing); err != nil {
			return err
		}
		if !WaitFor(ctx, podDeletionCheckInterval, podDeletionTimeout, func(ctx context.Context) bool {
			return replacedOrGone(ctx, client, key, &corev1.Pod{}, existing.UID)
		}) {
			return fmt.Errorf("timed out waiting for the old web terminal pod %v to be deleted", key)
		}
	}

	// a parallel session may have created the pod in the meantime, startProcess checks it is ours
	if err := client.Create(ctx, pod); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// podNeedsReplacement reports whether the existing pod cannot serve the desired one: it belongs to
// another identity or spec, it is terminating or finished, or it was created by an older version
// that mounted a kubeconfig Secret instead of running the proxy.
func podNeedsReplacement(existing, desired *corev1.Pod) bool {
	if existing.DeletionTimestamp != nil || !podMatches(existing, desired) {
		return true
	}
	if existing.Status.Phase == corev1.PodFailed || existing.Status.Phase == corev1.PodSucceeded {
		return true
	}
	for _, v := range existing.Spec.Volumes {
		if v.Secret != nil {
			return true
		}
	}
	return !slices.ContainsFunc(existing.Spec.Containers, func(c corev1.Container) bool {
		return c.Name == proxyContainerName
	})
}

// podMatches reports whether the existing pod was created for the identity and spec of the desired pod.
func podMatches(existing, desired *corev1.Pod) bool {
	return existing.Annotations[identityAnnotation] == desired.Annotations[identityAnnotation] &&
		existing.Annotations[specHashAnnotation] == desired.Annotations[specHashAnnotation]
}

// replacedOrGone reports whether the object with the key is gone or was recreated with a UID other
// than deletedUID, e.g. by a parallel session.
func replacedOrGone(ctx context.Context, client ctrlruntimeclient.Client, key ctrlruntimeclient.ObjectKey, obj ctrlruntimeclient.Object, deletedUID types.UID) bool {
	err := client.Get(ctx, key, obj)
	if apierrors.IsNotFound(err) {
		return true
	}
	return err == nil && obj.GetUID() != deletedUID && obj.GetDeletionTimestamp() == nil
}

// podSpecHash returns a fingerprint of the pod spec, so a changed spec (image, args, volumes,
// environment) replaces pods created from an older one.
func podSpecHash(spec corev1.PodSpec) string {
	raw, err := json.Marshal(spec)
	if err != nil {
		// cannot happen for a PodSpec, an empty hash only forces a new pod
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func deleteIgnoreNotFound(ctx context.Context, client ctrlruntimeclient.Client, obj ctrlruntimeclient.Object) error {
	return ctrlruntimeclient.IgnoreNotFound(client.Delete(ctx, obj))
}

// createOrUpdate creates obj or replaces the existing object with it.
func createOrUpdate(ctx context.Context, client ctrlruntimeclient.Client, obj ctrlruntimeclient.Object) error {
	err := client.Create(ctx, obj)
	if !apierrors.IsAlreadyExists(err) {
		return err
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		existing, ok := obj.DeepCopyObject().(ctrlruntimeclient.Object)
		if !ok {
			return fmt.Errorf("unexpected object type %T", obj)
		}
		if err := client.Get(ctx, ctrlruntimeclient.ObjectKeyFromObject(obj), existing); err != nil {
			return err
		}
		obj.SetResourceVersion(existing.GetResourceVersion())
		return client.Update(ctx, obj)
	})
}

// ensureCleanupJob creates the cleanup Job in the seed when it is missing and replaces a Job
// created by an older version whose script does not delete all web terminal resources.
func ensureCleanupJob(ctx context.Context, seedClient ctrlruntimeclient.Client, userEmailID, userAppName, clusterNamespace, overwriteRegistry string) error {
	cleanupJob := genWebTerminalCleanupJob(userAppName, userEmailID, clusterNamespace, overwriteRegistry)
	key := ctrlruntimeclient.ObjectKeyFromObject(cleanupJob)

	existing := &batchv1.Job{}
	err := seedClient.Get(ctx, key, existing)
	switch {
	case apierrors.IsNotFound(err):
		return createJob(ctx, seedClient, cleanupJob)
	case err != nil:
		return err
	case isCurrentCleanupJob(existing):
		return nil
	}

	if err := seedClient.Delete(ctx, existing, ctrlruntimeclient.PropagationPolicy(metav1.DeletePropagationBackground)); ctrlruntimeclient.IgnoreNotFound(err) != nil {
		return err
	}
	// wait until the old job is gone, otherwise the create below finds it and no current job is left.
	// A job with another UID was created by a parallel session in the meantime.
	if !WaitFor(ctx, time.Second, 30*time.Second, func(ctx context.Context) bool {
		return replacedOrGone(ctx, seedClient, key, &batchv1.Job{}, existing.UID)
	}) {
		return fmt.Errorf("timed out waiting for the old cleanup job %v to be deleted", key)
	}
	return createJob(ctx, seedClient, cleanupJob)
}

func createJob(ctx context.Context, seedClient ctrlruntimeclient.Client, job *batchv1.Job) error {
	if err := seedClient.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// isCurrentCleanupJob reports whether the job runs the current cleanup script. Jobs created by
// older versions do not have the WEBTERMINAL_RBAC_NAME env.
func isCurrentCleanupJob(job *batchv1.Job) bool {
	for _, c := range job.Spec.Template.Spec.Containers {
		for _, e := range c.Env {
			if e.Name == rbacNameEnv {
				return true
			}
		}
	}
	return false
}

func genWebTerminalServiceAccount(userAppName string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userAppName,
			Namespace: metav1.NamespaceSystem,
			Labels:    map[string]string{resources.AppLabelKey: appName},
		},
		AutomountServiceAccountToken: resources.Bool(false),
	}
}

// genWebTerminalClusterRole allows the web terminal ServiceAccount to impersonate the user and
// the user's groups, and nothing else.
func genWebTerminalClusterRole(userEmailID string, identity webTerminalIdentity) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   webTerminalRBACName(userEmailID),
			Labels: map[string]string{resources.AppLabelKey: appName},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"users"},
				Verbs:         []string{"impersonate"},
				ResourceNames: []string{identity.user},
			},
			{
				APIGroups:     []string{""},
				Resources:     []string{"groups"},
				Verbs:         []string{"impersonate"},
				ResourceNames: slices.Clone(identity.groups),
			},
		},
	}
}

func genWebTerminalClusterRoleBinding(userEmailID, userAppName string) *rbacv1.ClusterRoleBinding {
	name := webTerminalRBACName(userEmailID)
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{resources.AppLabelKey: appName},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      userAppName,
				Namespace: metav1.NamespaceSystem,
			},
		},
	}
}

// genWebTerminalKubeconfigConfigMap returns the kubeconfigs of the web terminal pod. Neither holds
// a credential. The shell talks to the proxy on localhost, the proxy reads the projected
// ServiceAccount token from a file.
func genWebTerminalKubeconfigConfigMap(userAppName string, cluster *kubermaticv1.Cluster) (*corev1.ConfigMap, error) {
	shellCfg := clientcmdapi.NewConfig()
	shellCfg.Clusters[cluster.Name] = &clientcmdapi.Cluster{Server: fmt.Sprintf("http://%s", net.JoinHostPort(proxyAddress, strconv.Itoa(proxyPort)))}
	shellCfg.AuthInfos[appName] = &clientcmdapi.AuthInfo{}
	shellCfg.Contexts[cluster.Name] = &clientcmdapi.Context{Cluster: cluster.Name, AuthInfo: appName}
	shellCfg.CurrentContext = cluster.Name

	shellKubeconfig, err := clientcmd.Write(*shellCfg)
	if err != nil {
		return nil, err
	}

	// kubectl ignores --as and --as-group with the in-cluster config, so the proxy gets its own
	// kubeconfig. It uses the external address of the API server, not the in-cluster Service IP:
	// with the Tunneling expose strategy the endpoints of that Service are the tunneling agent,
	// which the NetworkPolicy does not allow. The external name is in the serving certificate,
	// which is signed by the cluster CA from kube-root-ca.crt.
	if cluster.Status.Address.URL == "" {
		return nil, fmt.Errorf("cluster %s has no API server URL yet", cluster.Name)
	}
	proxyCfg := clientcmdapi.NewConfig()
	proxyCfg.Clusters[cluster.Name] = &clientcmdapi.Cluster{
		Server:               cluster.Status.Address.URL,
		CertificateAuthority: serviceAccountDir + "/ca.crt",
	}
	proxyCfg.AuthInfos[appName] = &clientcmdapi.AuthInfo{TokenFile: serviceAccountDir + "/token"}
	proxyCfg.Contexts[cluster.Name] = &clientcmdapi.Context{Cluster: cluster.Name, AuthInfo: appName}
	proxyCfg.CurrentContext = cluster.Name

	proxyKubeconfig, err := clientcmd.Write(*proxyCfg)
	if err != nil {
		return nil, err
	}

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      webTerminalKubeconfigConfigMapName(userAppName),
			Namespace: metav1.NamespaceSystem,
			Labels:    map[string]string{resources.AppLabelKey: appName},
		},
		Data: map[string]string{
			kubeconfigKey:      string(shellKubeconfig),
			proxyKubeconfigKey: string(proxyKubeconfig),
		},
	}, nil
}

func genWebTerminalConfigMap(userAppName string, numberOfExpirationRefreshes int) *corev1.ConfigMap {
	expirationTime := time.Now().Add(podLifetime)

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userAppName,
			Namespace: metav1.NamespaceSystem,
			Labels: map[string]string{
				resources.AppLabelKey: appName,
			},
		},
		Data: map[string]string{
			expirationTimestampKey: strconv.FormatInt(expirationTime.Unix(), 10),
			expirationRefreshesKey: strconv.Itoa(numberOfExpirationRefreshes),
		},
	}
}

func genWebTerminalNetworkPolicy(userAppName string, cluster *kubermaticv1.Cluster, options *kubermaticv1.WebTerminalOptions) (*networkingv1.NetworkPolicy, error) {
	dnsPort := intstr.FromInt(53)
	apiServicePort := intstr.FromInt(443)
	protoUdp := corev1.ProtocolUDP
	protoTcp := corev1.ProtocolTCP
	k8sApiIP := cluster.Status.Address.IP
	apiPort := intstr.FromInt(int(cluster.Status.Address.Port))

	k8sServiceApiIP, err := resources.InClusterApiserverIP(cluster)
	if err != nil {
		return nil, err
	}

	egressRules := []networkingv1.NetworkPolicyEgressRule{
		{
			To: []networkingv1.NetworkPolicyPeer{
				{
					IPBlock: &networkingv1.IPBlock{
						CIDR: fmt.Sprintf("%s/32", k8sApiIP),
					},
				},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{
					Protocol: &protoTcp,
					Port:     &apiPort,
				},
			},
		},
		{
			To: []networkingv1.NetworkPolicyPeer{
				{
					IPBlock: &networkingv1.IPBlock{
						CIDR: fmt.Sprintf("%s/32", k8sServiceApiIP),
					},
				},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{
					Protocol: &protoTcp,
					Port:     &apiServicePort,
				},
			},
		},
		// world dns access
		{
			To: []networkingv1.NetworkPolicyPeer{
				{
					IPBlock: &networkingv1.IPBlock{
						CIDR: "0.0.0.0/0",
					},
				},
			},
			Ports: []networkingv1.NetworkPolicyPort{
				{
					Protocol: &protoTcp,
					Port:     &dnsPort,
				},
				{
					Protocol: &protoUdp,
					Port:     &dnsPort,
				},
			},
		},
	}

	if options != nil && options.EnableInternetAccess {
		egressRules = []networkingv1.NetworkPolicyEgressRule{{}}
	}

	// block all ingress and allow only egress to the API server
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      userAppName,
			Namespace: metav1.NamespaceSystem,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					resources.AppLabelKey: appName,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			// api access
			Egress: egressRules,
		},
	}, nil
}

func genWebTerminalPod(userAppName string, identity webTerminalIdentity, options *kubermaticv1.WebTerminalOptions, overwriteRegistry string) *corev1.Pod {
	image := registry.Must(registry.RewriteImage(webTerminalImage, overwriteRegistry))

	pod := &corev1.Pod{}
	pod.Name = userAppName
	pod.Namespace = metav1.NamespaceSystem
	pod.Labels = map[string]string{
		resources.AppLabelKey: appName,
	}
	pod.Spec = corev1.PodSpec{
		ServiceAccountName:            userAppName,
		AutomountServiceAccountToken:  resources.Bool(false),
		ShareProcessNamespace:         resources.Bool(false),
		TerminationGracePeriodSeconds: ptr.To[int64](podTerminationGracePeriod),
	}
	pod.Spec.Volumes = getVolumes(userAppName)
	pod.Spec.InitContainers = []corev1.Container{}

	env := []corev1.EnvVar{
		{
			Name:  "KUBECONFIG",
			Value: webTerminalContainerKubeconfigPath,
		},
		{
			Name:  "PS1",
			Value: "\\s-\\v \\w \\$ ",
		},
		{
			Name:  "SSL_CERT_FILE",
			Value: webTerminalCABundlePath,
		},
	}

	if options != nil && options.AdditionalEnvironmentVariables != nil {
		env = append(env, options.AdditionalEnvironmentVariables...)
	}

	// --disable-filter is needed for kubectl exec, attach and port-forward, the default filter rejects
	// pods/*/exec. The proxy only listens on localhost inside the pod.
	proxyArgs := []string{
		"proxy",
		fmt.Sprintf("--address=%s", proxyAddress),
		fmt.Sprintf("--port=%d", proxyPort),
		"--disable-filter=true",
		fmt.Sprintf("--as=%s", identity.user),
	}
	for _, g := range identity.groups {
		proxyArgs = append(proxyArgs, fmt.Sprintf("--as-group=%s", g))
	}

	pod.Spec.Containers = []corev1.Container{
		{
			Name:         userAppName,
			Image:        image,
			Command:      []string{"/bin/bash", "-c", "--"},
			Args:         []string{"while true; do sleep 30; done;"},
			Env:          env,
			VolumeMounts: getVolumeMounts(),
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: resources.Bool(false),
			},
		},
		{
			Name:    proxyContainerName,
			Image:   image,
			Command: []string{"kubectl"},
			Args:    proxyArgs,
			Env: []corev1.EnvVar{
				{
					Name:  "KUBECONFIG",
					Value: proxyKubeconfigDir + "/" + kubeconfigKey,
				},
				{
					// kubectl keeps its cache below HOME, the root filesystem is read-only
					Name:  "HOME",
					Value: proxyHomeDir,
				},
			},
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      webTerminalProxyKubeconfigVolume,
					MountPath: proxyKubeconfigDir,
					ReadOnly:  true,
				},
				{
					Name:      proxyTmpDir,
					MountPath: proxyHomeDir,
				},
				{
					Name:      webTerminalServiceAccountVolume,
					MountPath: serviceAccountDir,
					ReadOnly:  true,
				},
			},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("10m"),
					corev1.ResourceMemory: resource.MustParse("32Mi"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("250m"),
					corev1.ResourceMemory: resource.MustParse("128Mi"),
				},
			},
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: resources.Bool(false),
				RunAsUser:                ptr.To[int64](proxyUser),
				RunAsGroup:               ptr.To[int64](proxyUser),
				RunAsNonRoot:             resources.Bool(true),
				ReadOnlyRootFilesystem:   resources.Bool(true),
				Capabilities: &corev1.Capabilities{
					Drop: []corev1.Capability{"ALL"},
				},
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			},
		},
	}

	pod.Annotations = map[string]string{
		identityAnnotation: identity.hash(),
		specHashAnnotation: podSpecHash(pod.Spec),
	}

	return pod
}

func genWebTerminalCleanupJob(userAppName, userEmailID, namespace, overwriteRegistry string) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("cleanup-%s", userAppName),
			Namespace: namespace,
			Labels: map[string]string{
				resources.AppLabelKey: appName,
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit:            resources.Int32(10 + maxNumberOfExpirationRefreshes),
			Completions:             resources.Int32(1),
			Parallelism:             resources.Int32(1),
			TTLSecondsAfterFinished: resources.Int32(0),
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Volumes:        getWebTerminalCleanJobVolumes(),
					InitContainers: []corev1.Container{},
					Containers: []corev1.Container{
						{
							Name:    userAppName,
							Image:   registry.Must(registry.RewriteImage(webTerminalImage, overwriteRegistry)),
							Command: []string{"/bin/bash", "-c"},
							Args: []string{`

								EXP=$(kubectl get configmap $USER_APP_NAME -n $NAMESPACE_SYSTEM -o jsonpath='{.data.ExpirationTimestamp}')
								EXP_REFRESHES=$(kubectl get configmap $USER_APP_NAME -n $NAMESPACE_SYSTEM -o jsonpath='{.data.ExpirationRefreshes}')
								NOW=$(date +"%s");
								REMAINING_TIME_SEC=$((EXP-NOW));
								if (( EXP_REFRESHES <= MAX_EXPIRATION_REFRESHES && REMAINING_TIME_SEC > 0 )); then
									sleep $REMAINING_TIME_SEC;
									exit 1; # exit as failed, so the job will be restarted to check if the expiration was updated
								fi
								# user web terminal is already expired, so delete its resources.
								# run every delete, but fail the job if any of them failed, so it gets retried
								rc=0
								kubectl delete clusterrolebinding $WEBTERMINAL_RBAC_NAME --ignore-not-found || rc=1
								kubectl delete clusterrole $WEBTERMINAL_RBAC_NAME --ignore-not-found || rc=1
								kubectl delete pod $USER_APP_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1
								kubectl delete serviceaccount $USER_APP_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1
								kubectl delete configmap $USER_APP_NAME-kubeconfig -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1
								kubectl delete secret $KUBECONFIG_SECRET_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1
								kubectl delete networkpolicy $USER_APP_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1
								kubectl delete configmap $USER_APP_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1
								exit $rc`,
							},
							Env: []corev1.EnvVar{
								{
									Name:  "KUBECONFIG",
									Value: webTerminalContainerKubeconfigPath,
								},
								{
									Name:  "USER_APP_NAME",
									Value: userAppName,
								},
								{
									Name:  "NAMESPACE_SYSTEM",
									Value: metav1.NamespaceSystem,
								},
								{
									Name:  rbacNameEnv,
									Value: webTerminalRBACName(userEmailID),
								},
								{
									// the kubeconfig Secret of the old token based model
									Name:  kubeconfigSecretNameEnv,
									Value: handlercommon.KubeconfigSecretName(userEmailID),
								},
								{
									Name:  "MAX_EXPIRATION_REFRESHES",
									Value: strconv.Itoa(maxNumberOfExpirationRefreshes),
								},
								{
									Name:  "PS1",
									Value: "\\$ ",
								},
							},
							VolumeMounts: getWebTerminalCleanJobVolumeMounts(),
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: resources.Bool(false),
							},
						},
					},
					RestartPolicy: corev1.RestartPolicyOnFailure,
				},
			},
		},
	}
}

func getVolumes(userAppName string) []corev1.Volume {
	vs := []corev1.Volume{
		{
			Name: webTerminalKubeconfigVolume,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: webTerminalKubeconfigConfigMapName(userAppName),
					},
					Items: []corev1.KeyToPath{
						{
							Key:  kubeconfigKey,
							Path: kubeconfigKey,
						},
					},
				},
			},
		},
		{
			Name: webTerminalProxyKubeconfigVolume,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: webTerminalKubeconfigConfigMapName(userAppName),
					},
					Items: []corev1.KeyToPath{
						{
							Key:  proxyKubeconfigKey,
							Path: kubeconfigKey,
						},
					},
				},
			},
		},
		{
			// the same files as the default ServiceAccount token volume, but only mounted in the proxy
			Name: webTerminalServiceAccountVolume,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{
						{
							ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
								ExpirationSeconds: ptr.To[int64](serviceAccountTokenExpiration),
								Path:              "token",
							},
						},
						{
							ConfigMap: &corev1.ConfigMapProjection{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: "kube-root-ca.crt",
								},
								Items: []corev1.KeyToPath{
									{
										Key:  "ca.crt",
										Path: "ca.crt",
									},
								},
							},
						},
						{
							DownwardAPI: &corev1.DownwardAPIProjection{
								Items: []corev1.DownwardAPIVolumeFile{
									{
										Path: "namespace",
										FieldRef: &corev1.ObjectFieldSelector{
											APIVersion: "v1",
											FieldPath:  "metadata.namespace",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Name: webTerminalStorage,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumMemory,
				},
			},
		},
		{
			Name: proxyTmpDir,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					SizeLimit: ptr.To(resource.MustParse("64Mi")),
				},
			},
		},
		{
			Name: webTerminalConfigVolume,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: userAppName,
					},
					Items: []corev1.KeyToPath{
						{
							Key:  expirationTimestampKey,
							Path: "expiration",
						},
						{
							Key:  expirationRefreshesKey,
							Path: "expiration-refreshes",
						},
					},
				},
			},
		},
		{
			Name: webTerminalCABundleVolume,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: resources.CABundleConfigMapName,
					},
					Items: []corev1.KeyToPath{
						{
							Key:  resources.CABundleConfigMapKey,
							Path: resources.CABundleConfigMapKey,
						},
					},
				},
			},
		},
	}
	return vs
}

func getWebTerminalCleanJobVolumes() []corev1.Volume {
	vs := []corev1.Volume{
		{
			Name: resources.AdminKubeconfigSecretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: resources.AdminKubeconfigSecretName,
				},
			},
		},
	}
	return vs
}

func getWebTerminalCleanJobVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{
			Name:      resources.AdminKubeconfigSecretName,
			MountPath: "/etc/kubernetes/kubeconfig",
			ReadOnly:  true,
		},
	}
}

func getVolumeMounts() []corev1.VolumeMount {
	return []corev1.VolumeMount{
		{
			Name:      webTerminalKubeconfigVolume,
			MountPath: "/etc/kubernetes/kubeconfig",
			ReadOnly:  true,
		},
		{
			Name:      webTerminalStorage,
			ReadOnly:  false,
			MountPath: "/data/terminal",
		},
		{
			Name:      webTerminalConfigVolume,
			MountPath: "/etc/config",
		},
		{
			Name:      webTerminalCABundleVolume,
			MountPath: webTerminalCABundleDir,
			ReadOnly:  true,
		},
	}
}

// Terminal is called for any new websocket connection. claims are the claims of the token of the
// KKP user, seed is the seed of the cluster.
func Terminal(ctx context.Context, ws *websocket.Conn, client, seedClient ctrlruntimeclient.Client, k8sClient kubernetes.Interface, cfg *rest.Config, claims authtypes.TokenClaims, seed *kubermaticv1.Seed, cluster *kubermaticv1.Cluster, options *kubermaticv1.WebTerminalOptions, overwriteRegistry string) {
	if claims.Email == "" {
		log.Logger.Debug("the web terminal needs the email of the user")
		return
	}

	identity, err := resolveWebTerminalIdentity(cluster, seed, claims)
	if err != nil {
		log.Logger.Debugw("refusing to start the web terminal", "cluster", cluster.Name, "error", err)
		_ = SendMessage(ws, string(identityErrorStatus(err)))
		return
	}

	userEmailID := EncodeUserEmailtoID(claims.Email)

	if err := startProcess(
		ctx,
		client,
		seedClient,
		k8sClient,
		cfg,
		identity,
		userEmailID,
		cluster,
		options,
		overwriteRegistry,
		[]string{"bash", "-c", "cd /data/terminal && /bin/bash"},
		TerminalSession{
			websocketConn: ws,
			userEmailID:   userEmailID,
			clusterClient: client,
			sizeChan:      make(chan remotecommand.TerminalSize),
			doneChan:      make(chan struct{}),
		},
		ws); err != nil {
		log.Logger.Debug(err)
		return
	}
}

// identityErrorStatus returns the status message sent to the UI for an identity error.
func identityErrorStatus(err error) TerminalConnStatus {
	if errors.Is(err, errIdentityRejected) {
		return WebTerminalIdentityRejected
	}
	return WebTerminalIdentityUnsupported
}

// EncodeUserEmailtoID returns the ID used to name the web terminal resources of a user.
// It ignores the case of the email, see handlercommon.EncodeUserEmailToID.
func EncodeUserEmailtoID(email string) string {
	return handlercommon.EncodeUserEmailToID(email)
}

// WaitFor is a function to wait until callback function return true.
func WaitFor(ctx context.Context, interval time.Duration, timeout time.Duration, callback func(ctx context.Context) bool) bool {
	err := wait.PollUntilContextTimeout(ctx, interval, timeout, true, func(ctx context.Context) (bool, error) {
		return callback(ctx), nil
	})
	return err == nil
}

// SendMessage sends TerminalMessage to the client. It usually contains a context related
// to the status of background tasks responsible for setting up the terminal.
func SendMessage(wsConn jsonWriter, message string) error {
	return wsConn.WriteJSON(TerminalMessage{
		Op:   "msg",
		Data: message,
	})
}
