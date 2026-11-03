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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/util/retry"
	"k8s.io/kubectl/pkg/scheme"
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
	remainingTokenExpirationTime      = 5 * time.Minute
	expirationTimestampKey            = "ExpirationTimestamp"
	expirationRefreshesKey            = "ExpirationRefreshes"
	pingInterval                      = 30 * time.Second
	pingMessage                       = "PING"
	pongMessage                       = "PONG"

	kubeconfigSecretNameEnv = "KUBECONFIG_SECRET_NAME"

	webTerminalImage                   = resources.WEBTerminalImage
	webTerminalContainerKubeconfigPath = "/etc/kubernetes/kubeconfig/kubeconfig"

	webTerminalCABundleVolume = "ca-bundle"
	webTerminalCABundleDir    = "/etc/kubermatic/certs"
	webTerminalCABundlePath   = webTerminalCABundleDir + "/" + resources.CABundleConfigMapKey
)

type TerminalConnStatus string

const (
	KubeconfigSecretMissing TerminalConnStatus = "KUBECONFIG_SECRET_MISSING"
	KubeconfigSecretInvalid TerminalConnStatus = "KUBECONFIG_SECRET_INVALID"
	WebTerminalTokenExpired TerminalConnStatus = "WEBTERMINAL_TOKEN_EXPIRED"
	WebTerminalTokenValid   TerminalConnStatus = "WEBTERMINAL_TOKEN_VALID"
	WebterminalPodPending   TerminalConnStatus = "WEBTERMINAL_POD_PENDING"
	WebterminalPodFailed    TerminalConnStatus = "WEBTERMINAL_POD_FAILED"
	ConnectionPoolExceeded  TerminalConnStatus = "CONNECTION_POOL_EXCEEDED"
	RefreshesLimitExceeded  TerminalConnStatus = "REFRESHES_LIMIT_EXCEEDED"
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

// checkTokenAndRefreshIfNeeded keeps the ID token in the user cluster kubeconfig Secret fresh while the
// terminal session is open. The refresh token is read from and written back to a Secret in the seed
// cluster namespace, so it never reaches the user cluster.
func checkTokenAndRefreshIfNeeded(ctx context.Context, clusterClient, seedClient ctrlruntimeclient.Client, clusterNamespace, userEmailID string, oidcIssuerVerifier authtypes.OIDCIssuerVerifier, kubeconfigSecret *corev1.Secret, websocketConn jsonWriter) {
	seedSecretKey := ctrlruntimeclient.ObjectKey{
		Namespace: clusterNamespace,
		Name:      handlercommon.WebTerminalOIDCSecretName(userEmailID),
	}

	for {
		// Update the kubeconfig secret in case it gets recreated.
		if err := clusterClient.Get(ctx, ctrlruntimeclient.ObjectKey{
			Namespace: metav1.NamespaceSystem,
			Name:      kubeconfigSecret.Name,
		}, kubeconfigSecret); err != nil {
			log.Logger.Debug(err)
			_ = SendMessage(websocketConn, string(KubeconfigSecretMissing))
			if !sleepCtx(ctx, 5*time.Second) {
				return
			}
			continue
		}
		cfg, err := clientcmd.Load(kubeconfigSecret.Data["kubeconfig"])
		if err != nil {
			log.Logger.Debug(err)
			_ = SendMessage(websocketConn, string(KubeconfigSecretInvalid))
			if !sleepCtx(ctx, 5*time.Second) {
				return
			}
			continue
		}

		user, err := getFirstUser(cfg.AuthInfos)
		if err != nil {
			log.Logger.Debug(err)
			_ = SendMessage(websocketConn, string(KubeconfigSecretInvalid))
			if !sleepCtx(ctx, 5*time.Second) {
				return
			}
			continue
		}

		// kubeconfigs written before the refresh token moved to the seed still hold the refresh token and
		// the client secret. Delete them, the UI then runs the login popup again which writes the new format.
		if user.AuthProvider != nil {
			if err := clusterClient.Delete(ctx, kubeconfigSecret); ctrlruntimeclient.IgnoreNotFound(err) != nil {
				log.Logger.Debug(err)
			}
			_ = SendMessage(websocketConn, string(KubeconfigSecretMissing))
			if !sleepCtx(ctx, 5*time.Second) {
				return
			}
			continue
		}

		tokenExpirationTime, err := GetTokenExpiration(user.Token)
		if err != nil {
			log.Logger.Debug(err)
			if !onFailedUpdatingToken(ctx, websocketConn, tokenExpirationTime) {
				return
			}
			continue
		}

		// Only refresh the token when it’s close to expiring.
		threshold := tokenRefreshThreshold(user.Token)
		if time.Until(tokenExpirationTime) <= threshold {
			tokenExpirationTime, err = refreshToken(ctx, clusterClient, seedClient, seedSecretKey, oidcIssuerVerifier, kubeconfigSecret, cfg, user)
			if err != nil {
				log.Logger.Debug(err)
				if !onFailedUpdatingToken(ctx, websocketConn, tokenExpirationTime) {
					return
				}
				continue
			}
			threshold = tokenRefreshThreshold(user.Token)
		}

		// check again when the token reaches the refresh threshold or at the token expiration time
		_ = SendMessage(websocketConn, string(WebTerminalTokenValid))
		sleepDuration := time.Until(tokenExpirationTime) - threshold
		if sleepDuration <= 0 {
			sleepDuration = time.Until(tokenExpirationTime)
		}
		if !sleepCtx(ctx, sleepDuration) {
			return
		}
	}
}

// refreshToken renews the ID token with the refresh token from the seed Secret. It stores the new
// refresh token in the seed Secret first, so a failed user cluster update does not lose a rotated
// refresh token. It returns the expiry of the token that is in the kubeconfig afterwards.
func refreshToken(ctx context.Context, clusterClient, seedClient ctrlruntimeclient.Client, seedSecretKey ctrlruntimeclient.ObjectKey, oidcIssuerVerifier authtypes.OIDCIssuerVerifier, kubeconfigSecret *corev1.Secret, cfg *clientcmdapi.Config, user *clientcmdapi.AuthInfo) (time.Time, error) {
	currentExpiration, _ := GetTokenExpiration(user.Token)

	seedSecret := &corev1.Secret{}
	if err := seedClient.Get(ctx, seedSecretKey, seedSecret); err != nil {
		return currentExpiration, fmt.Errorf("failed to get refresh token secret: %w", err)
	}
	oldRefreshToken := string(seedSecret.Data[handlercommon.WebTerminalOIDCRefreshTokenKey])
	if oldRefreshToken == "" {
		return currentExpiration, errors.New("refresh token secret has no refresh token")
	}

	newToken, err := oidcIssuerVerifier.RefreshAccessToken(ctx, oldRefreshToken)
	if err != nil {
		return currentExpiration, err
	}

	newExpiration, err := GetTokenExpiration(newToken.IDToken)
	if err != nil {
		return currentExpiration, err
	}

	if newToken.RefreshToken != "" && newToken.RefreshToken != oldRefreshToken {
		seedSecret.Data[handlercommon.WebTerminalOIDCRefreshTokenKey] = []byte(newToken.RefreshToken)
		if err := seedClient.Update(ctx, seedSecret); err != nil {
			return currentExpiration, fmt.Errorf("failed to store refresh token: %w", err)
		}
	}

	user.Token = newToken.IDToken
	updatedKubeconfig, err := clientcmd.Write(*cfg)
	if err != nil {
		return currentExpiration, err
	}
	kubeconfigSecret.Data["kubeconfig"] = updatedKubeconfig
	if err := clusterClient.Update(ctx, kubeconfigSecret); err != nil {
		return currentExpiration, err
	}

	return newExpiration, nil
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

// startProcess is called by terminal session creation.
// Executed cmd in the container specified in request and connects it up with the ptyHandler (a session).
func startProcess(ctx context.Context, client, seedClient ctrlruntimeclient.Client, k8sClient kubernetes.Interface, cfg *rest.Config, userEmailID string, cluster *kubermaticv1.Cluster, options *kubermaticv1.WebTerminalOptions, oidcIssuerVerifier authtypes.OIDCIssuerVerifier, kubeconfigSecret *corev1.Secret, overwriteRegistry string, cmd []string, ptyHandler PtyHandler, websocketConn *websocket.Conn) error {
	userAppName := userAppName(userEmailID)
	if err := prepareResources(ctx, client, seedClient, userEmailID, userAppName, cluster, options, overwriteRegistry); err != nil {
		return err
	}

	if !WaitFor(ctx, 5*time.Second, timeout, func(ctx context.Context) bool {
		pod := &corev1.Pod{}
		if err := client.Get(ctx, ctrlruntimeclient.ObjectKey{
			Namespace: metav1.NamespaceSystem,
			Name:      userAppName,
		}, pod); err != nil {
			return false
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

	go pingRoutine(ctx, websocketConn)

	go expirationCheckRoutine(ctx, client, userEmailID, websocketConn)

	go checkTokenAndRefreshIfNeeded(ctx, client, seedClient, cluster.Status.NamespaceName, userEmailID, oidcIssuerVerifier, kubeconfigSecret, websocketConn)

	req := k8sClient.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(userAppName).
		Namespace(metav1.NamespaceSystem).
		SubResource("exec")

	req.VersionedParams(&corev1.PodExecOptions{
		Command: cmd,
		Stdin:   true,
		Stdout:  true,
		Stderr:  true,
		TTY:     true,
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

// prepareResources creates the user cluster resources of the web terminal when its pod is missing,
// makes sure the cleanup Job exists and renews the expiration ConfigMap.
func prepareResources(ctx context.Context, client, seedClient ctrlruntimeclient.Client, userEmailID, userAppName string, cluster *kubermaticv1.Cluster, options *kubermaticv1.WebTerminalOptions, overwriteRegistry string) error {
	// check if WEB terminal Pod exists, if not create
	pod := &corev1.Pod{}
	if err := client.Get(ctx, ctrlruntimeclient.ObjectKey{
		Namespace: metav1.NamespaceSystem,
		Name:      userAppName,
	}, pod); err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		// create NetworkPolicy and Pod
		if err := createOrUpdateResources(ctx, client, userEmailID, userAppName, cluster, options, overwriteRegistry); err != nil {
			return err
		}
	}

	// the job can be gone while the pod still exists, e.g. when the pod is still terminating,
	// so check it on every session
	if err := ensureCleanupJob(ctx, seedClient, userEmailID, userAppName, cluster.Status.NamespaceName, overwriteRegistry); err != nil {
		return err
	}

	// create or update ConfigMap to renew expiration time
	if err := client.Create(ctx, genWebTerminalConfigMap(userAppName, 0)); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		err := client.Update(ctx, genWebTerminalConfigMap(userAppName, 0))
		if err != nil {
			return err
		}
	}

	return nil
}

func createOrUpdateResources(ctx context.Context, client ctrlruntimeclient.Client, userEmailID, userAppName string, cluster *kubermaticv1.Cluster, options *kubermaticv1.WebTerminalOptions, overwriteRegistry string) error {
	webTerminalNetworkPolicy, err := genWebTerminalNetworkPolicy(userAppName, cluster, options)
	if err != nil {
		return err
	}
	if err := client.Create(ctx, webTerminalNetworkPolicy); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
		err := client.Update(ctx, webTerminalNetworkPolicy)
		if err != nil {
			return err
		}
	}

	if err := client.Create(ctx, genWebTerminalPod(userAppName, userEmailID, options, overwriteRegistry)); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return err
		}
	}

	return nil
}

// ensureCleanupJob creates the cleanup Job in the seed when it is missing, replaces a Job created
// before the upgrade whose script does not delete the kubeconfig Secret, and makes the Job the owner
// of the seed Secret with the refresh token.
func ensureCleanupJob(ctx context.Context, seedClient ctrlruntimeclient.Client, userEmailID, userAppName, clusterNamespace, overwriteRegistry string) error {
	cleanupJob := genWebTerminalCleanupJob(userAppName, userEmailID, clusterNamespace, overwriteRegistry)
	key := ctrlruntimeclient.ObjectKeyFromObject(cleanupJob)

	existing := &batchv1.Job{}
	err := seedClient.Get(ctx, key, existing)
	switch {
	case err == nil && !cleanupJobDeletesKubeconfigSecret(existing):
		if err := seedClient.Delete(ctx, existing, ctrlruntimeclient.PropagationPolicy(metav1.DeletePropagationBackground)); ctrlruntimeclient.IgnoreNotFound(err) != nil {
			return err
		}
		// wait until the old job is gone, otherwise the create below finds it and the Secret gets the old owner
		if !WaitFor(ctx, time.Second, 30*time.Second, func(ctx context.Context) bool {
			return apierrors.IsNotFound(seedClient.Get(ctx, key, &batchv1.Job{}))
		}) {
			return fmt.Errorf("timed out waiting for the old cleanup job %v to be deleted", key)
		}
		if err := createJob(ctx, seedClient, cleanupJob); err != nil {
			return err
		}
	case apierrors.IsNotFound(err):
		if err := createJob(ctx, seedClient, cleanupJob); err != nil {
			return err
		}
	case err != nil:
		return err
	}

	// read the job back, the UID is needed for the owner reference
	if err := seedClient.Get(ctx, key, cleanupJob); err != nil {
		return err
	}

	return setWebTerminalOIDCSecretOwner(ctx, seedClient, userEmailID, cleanupJob)
}

func createJob(ctx context.Context, seedClient ctrlruntimeclient.Client, job *batchv1.Job) error {
	if err := seedClient.Create(ctx, job); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// cleanupJobDeletesKubeconfigSecret reports whether the job runs the current cleanup script, which also
// deletes the kubeconfig Secret. Jobs created by older versions do not have the KUBECONFIG_SECRET_NAME env.
func cleanupJobDeletesKubeconfigSecret(job *batchv1.Job) bool {
	for _, c := range job.Spec.Template.Spec.Containers {
		for _, e := range c.Env {
			if e.Name == kubeconfigSecretNameEnv {
				return true
			}
		}
	}
	return false
}

// setWebTerminalOIDCSecretOwner makes the cleanup Job the owner of the seed Secret that holds the
// refresh token, so garbage collection deletes the Secret together with the Job. It does nothing
// when the Secret does not exist.
func setWebTerminalOIDCSecretOwner(ctx context.Context, seedClient ctrlruntimeclient.Client, userEmailID string, job *batchv1.Job) error {
	key := ctrlruntimeclient.ObjectKey{
		Namespace: job.Namespace,
		Name:      handlercommon.WebTerminalOIDCSecretName(userEmailID),
	}
	ownerRef := metav1.OwnerReference{
		APIVersion:         batchv1.SchemeGroupVersion.String(),
		Kind:               "Job",
		Name:               job.Name,
		UID:                job.UID,
		Controller:         resources.Bool(false),
		BlockOwnerDeletion: resources.Bool(false),
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		secret := &corev1.Secret{}
		if err := seedClient.Get(ctx, key, secret); err != nil {
			return ctrlruntimeclient.IgnoreNotFound(err)
		}

		// drop references to earlier jobs with the same name, they are already gone
		refs := []metav1.OwnerReference{}
		for _, ref := range secret.OwnerReferences {
			if ref.UID == job.UID {
				return nil
			}
			if ref.Kind == ownerRef.Kind && ref.Name == ownerRef.Name {
				continue
			}
			refs = append(refs, ref)
		}
		refs = append(refs, ownerRef)
		secret.OwnerReferences = refs

		return seedClient.Update(ctx, secret)
	})
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

func genWebTerminalPod(userAppName, userEmailID string, options *kubermaticv1.WebTerminalOptions, overwriteRegistry string) *corev1.Pod {
	pod := &corev1.Pod{}
	pod.Name = userAppName
	pod.Namespace = metav1.NamespaceSystem
	pod.Labels = map[string]string{
		resources.AppLabelKey: appName,
	}
	pod.Spec = corev1.PodSpec{}
	pod.Spec.Volumes = getVolumes(userEmailID, userAppName)
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

	pod.Spec.Containers = []corev1.Container{
		{
			Name:         userAppName,
			Image:        registry.Must(registry.RewriteImage(webTerminalImage, overwriteRegistry)),
			Command:      []string{"/bin/bash", "-c", "--"},
			Args:         []string{"while true; do sleep 30; done;"},
			Env:          env,
			VolumeMounts: getVolumeMounts(),
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: resources.Bool(false),
			},
		},
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
								kubectl delete secret $KUBECONFIG_SECRET_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1
								kubectl delete networkpolicy $USER_APP_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1
								kubectl delete configmap $USER_APP_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1
								kubectl delete pod $USER_APP_NAME -n $NAMESPACE_SYSTEM --ignore-not-found || rc=1
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

func getVolumes(userEmailID, userAppName string) []corev1.Volume {
	vs := []corev1.Volume{
		{
			Name: resources.WEBTerminalKubeconfigSecretName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: handlercommon.KubeconfigSecretName(userEmailID),
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
			Name:      resources.WEBTerminalKubeconfigSecretName,
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

// Terminal is called for any new websocket connection.
func Terminal(ctx context.Context, ws *websocket.Conn, client, seedClient ctrlruntimeclient.Client, k8sClient kubernetes.Interface, cfg *rest.Config, userEmailID string, cluster *kubermaticv1.Cluster, options *kubermaticv1.WebTerminalOptions, oidcIssuerVerifier authtypes.OIDCIssuerVerifier, kubeconfigSecret *corev1.Secret, overwriteRegistry string) {
	if err := startProcess(
		ctx,
		client,
		seedClient,
		k8sClient,
		cfg,
		userEmailID,
		cluster,
		options,
		oidcIssuerVerifier,
		kubeconfigSecret,
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

// The kubeconfig secret must contain a single user, so we return the first one.
func getFirstUser(authInfos map[string]*clientcmdapi.AuthInfo) (*clientcmdapi.AuthInfo, error) {
	for _, u := range authInfos {
		return u, nil
	}
	return nil, fmt.Errorf("no user found in kubeconfig")
}

// tokenRefreshThreshold returns how long before expiry the token gets refreshed: half of its lifetime,
// at most remainingTokenExpirationTime. Short-lived tokens (e.g. 5 minutes) are so refreshed before they expire.
func tokenRefreshThreshold(token string) time.Duration {
	claims, err := tokenClaims(token)
	if err != nil {
		return remainingTokenExpirationTime
	}
	iat, okIat := claims["iat"].(float64)
	exp, okExp := claims["exp"].(float64)
	if !okIat || !okExp || exp <= iat {
		return remainingTokenExpirationTime
	}

	half := time.Duration(exp-iat) * time.Second / 2
	return min(half, remainingTokenExpirationTime)
}

// IsLegacyKubeconfigSecret reports whether a web terminal kubeconfig Secret uses the old format with
// the OIDC auth provider, which holds the refresh token and the client secret.
func IsLegacyKubeconfigSecret(secret *corev1.Secret) bool {
	cfg, err := clientcmd.Load(secret.Data["kubeconfig"])
	if err != nil {
		return false
	}
	for _, authInfo := range cfg.AuthInfos {
		if authInfo != nil && authInfo.AuthProvider != nil {
			return true
		}
	}
	return false
}

func tokenClaims(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}
	return claims, nil
}

func GetTokenExpiration(token string) (time.Time, error) {
	claims, err := tokenClaims(token)
	if err != nil {
		return time.Time{}, err
	}

	expFloat, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}, fmt.Errorf("exp claim missing")
	}

	return time.Unix(int64(expFloat), 0), nil
}

// onFailedUpdatingToken waits before the next refresh attempt. It returns false when ctx is done.
func onFailedUpdatingToken(ctx context.Context, websocketConn jsonWriter, tokenExpirationTime time.Time) bool {
	// If the token is already expired, send a message to the client and check every 5 seconds if the user authenticates again (update the kubeconfig secret).
	if time.Until(tokenExpirationTime) <= 0 {
		log.Logger.Debug("Token is already expired, and cannot be refreshed")
		_ = SendMessage(websocketConn, string(WebTerminalTokenExpired))
		return sleepCtx(ctx, 5*time.Second)
	}

	// If the token is still valid but can't be refreshed, try again after 1 minute.
	if time.Until(tokenExpirationTime) <= 1*time.Minute {
		// wait until the token is expired
		if !sleepCtx(ctx, time.Until(tokenExpirationTime)) {
			return false
		}
	}
	return sleepCtx(ctx, 1*time.Minute)
}
