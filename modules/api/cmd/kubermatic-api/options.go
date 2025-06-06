/*
Copyright 2020 The Kubermatic Kubernetes Platform contributors.

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

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/gorilla/securecookie"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"k8c.io/dashboard/v2/pkg/provider"
	authtypes "k8c.io/dashboard/v2/pkg/provider/auth/types"
	"k8c.io/dashboard/v2/pkg/serviceaccount"
	"k8c.io/dashboard/v2/pkg/watcher"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/defaulting"
	"k8c.io/kubermatic/v2/pkg/features"
	kubermaticlog "k8c.io/kubermatic/v2/pkg/log"
	"k8c.io/kubermatic/v2/pkg/resources/certificates"
	"k8c.io/kubermatic/v2/pkg/version/kubermatic"
)

type serverRunOptions struct {
	listenAddress                  string
	internalAddr                   string
	prometheusURL                  string
	workerName                     string
	swaggerFile                    string
	domain                         string
	exposeStrategy                 kubermaticv1.ExposeStrategy
	namespace                      string
	log                            kubermaticlog.Options
	caBundle                       *certificates.CABundle
	oidcIssuerConfiguration        *authtypes.OIDCConfiguration
	oidcAuthenticatorConfiguration *authtypes.OIDCConfiguration

	// for development purposes, a local configuration file
	// can be used to provide the KubermaticConfiguration
	kubermaticConfiguration *kubermaticv1.KubermaticConfiguration

	// OIDC configuration
	oidcURL                        string
	oidcAuthenticatorClientID      string
	oidcIssuerClientID             string
	oidcIssuerClientSecret         string
	oidcIssuerRedirectURI          string
	oidcIssuerCookieHashKey        string
	oidcIssuerCookieSecureMode     bool
	oidcSkipTLSVerify              bool
	oidcIssuerOfflineAccessAsScope bool

	// service account configuration
	serviceAccountSigningKey string

	featureGates features.FeatureGate
	versions     kubermatic.Versions
}

func newServerRunOptions() (serverRunOptions, error) {
	s := serverRunOptions{featureGates: features.FeatureGate{}}
	var (
		rawExposeStrategy string
		caBundleFile      string
		configFile        string
	)

	s.log = kubermaticlog.NewDefaultOptions()
	s.log.AddFlags(flag.CommandLine)

	flag.StringVar(&s.listenAddress, "address", ":8080", "The address to listen on")
	flag.StringVar(&s.internalAddr, "internal-address", "127.0.0.1:8085", "The address on which the internal handler should be exposed")
	flag.StringVar(&s.prometheusURL, "prometheus-url", "http://prometheus.monitoring.svc.local:web", "The URL on which this API can talk to Prometheus")
	flag.StringVar(&s.workerName, "worker-name", "", "Create clusters only processed by worker-name cluster controller")
	flag.StringVar(&s.swaggerFile, "swagger", "./cmd/kubermatic-api/swagger.json", "The swagger.json file path")
	flag.StringVar(&caBundleFile, "ca-bundle", "", "The path to the certificate for the CA that signed your identity provider’s web certificate.")
	flag.StringVar(&s.oidcURL, "oidc-url", "", "URL of the OpenID token issuer. Example: http://auth.int.kubermatic.io")
	flag.BoolVar(&s.oidcSkipTLSVerify, "oidc-skip-tls-verify", false, "Skip TLS verification for the token issuer")
	flag.StringVar(&s.oidcAuthenticatorClientID, "oidc-authenticator-client-id", "", "Authenticator client ID")
	flag.StringVar(&s.oidcIssuerClientID, "oidc-issuer-client-id", "", "Issuer client ID")
	flag.StringVar(&s.oidcIssuerClientSecret, "oidc-issuer-client-secret", "", "OpenID client secret")
	flag.StringVar(&s.oidcIssuerRedirectURI, "oidc-issuer-redirect-uri", "", "Callback URL for OpenID responses.")
	flag.StringVar(&s.oidcIssuerCookieHashKey, "oidc-issuer-cookie-hash-key", "", "Hash key authenticates the cookie value using HMAC. It is recommended to use a key with 32 or 64 bytes.")
	flag.BoolVar(&s.oidcIssuerCookieSecureMode, "oidc-issuer-cookie-secure-mode", true, "When true cookie received only with HTTPS. Set false for local deployment with HTTP")
	flag.BoolVar(&s.oidcIssuerOfflineAccessAsScope, "oidc-issuer-offline-access-as-scope", true, "Set it to false if OIDC provider requires to set \"access_type=offline\" query param when accessing the refresh token")
	flag.Var(&s.featureGates, "feature-gates", "A set of key=value pairs that describe feature gates for various features.")
	flag.StringVar(&s.domain, "domain", "localhost", "A domain name on which the server is deployed")
	flag.StringVar(&s.serviceAccountSigningKey, "service-account-signing-key", "", "Signing key authenticates the service account's token value using HMAC. It is recommended to use a key with 32 bytes or longer.")
	flag.StringVar(&rawExposeStrategy, "expose-strategy", "NodePort", "The strategy to expose the controlplane with, either \"NodePort\" which creates NodePorts with a \"nodeport-proxy.k8s.io/expose: true\" annotation or \"LoadBalancer\", which creates a LoadBalancer")
	flag.StringVar(&s.namespace, "namespace", "kubermatic", "The namespace kubermatic runs in, uses to determine where to look for datacenter custom resources")
	flag.StringVar(&configFile, "kubermatic-configuration-file", "", "(for development only) path to a KubermaticConfiguration YAML file")
	addFlags(flag.CommandLine)
	flag.Parse()

	var validExposeStrategy bool
	s.exposeStrategy, validExposeStrategy = kubermaticv1.ExposeStrategyFromString(rawExposeStrategy)
	if !validExposeStrategy {
		return s, fmt.Errorf("--expose-strategy must be one of: %s, got %q", kubermaticv1.AllExposeStrategies, rawExposeStrategy)
	}

	if configFile != "" {
		var err error
		if s.kubermaticConfiguration, err = loadKubermaticConfiguration(configFile); err != nil {
			return s, fmt.Errorf("invalid KubermaticConfiguration: %w", err)
		}
	}

	if len(caBundleFile) == 0 {
		return s, errors.New("no -ca-bundle configured")
	}

	cabundle, err := certificates.NewCABundleFromFile(caBundleFile)
	if err != nil {
		return s, fmt.Errorf("failed to read CA bundle file '%s': %w", caBundleFile, err)
	}

	s.caBundle = cabundle
	s.versions = kubermatic.GetVersions()

	s.oidcIssuerConfiguration = &authtypes.OIDCConfiguration{
		URL:                  s.oidcURL,
		ClientID:             s.oidcIssuerClientID,
		ClientSecret:         s.oidcIssuerClientSecret,
		SecureCookie:         securecookie.New([]byte(s.oidcIssuerCookieHashKey), nil),
		CookieSecureMode:     s.oidcIssuerCookieSecureMode,
		OfflineAccessAsScope: s.oidcIssuerOfflineAccessAsScope,
		SkipTLSVerify:        s.oidcSkipTLSVerify,
	}

	s.oidcAuthenticatorConfiguration = &authtypes.OIDCConfiguration{
		URL:           s.oidcURL,
		ClientID:      s.oidcAuthenticatorClientID,
		SkipTLSVerify: s.oidcSkipTLSVerify,
	}

	return s, nil
}

func (o serverRunOptions) validate() error {
	if err := serviceaccount.ValidateKey([]byte(o.serviceAccountSigningKey)); err != nil {
		return fmt.Errorf("the service-account-signing-key is incorrect: %w", err)
	}

	return nil
}

type providers struct {
	sshKey                                         provider.SSHKeyProvider
	privilegedSSHKeyProvider                       provider.PrivilegedSSHKeyProvider
	user                                           provider.UserProvider
	serviceAccountProvider                         provider.ServiceAccountProvider
	privilegedServiceAccountProvider               provider.PrivilegedServiceAccountProvider
	serviceAccountTokenProvider                    provider.ServiceAccountTokenProvider
	privilegedServiceAccountTokenProvider          provider.PrivilegedServiceAccountTokenProvider
	project                                        provider.ProjectProvider
	privilegedProject                              provider.PrivilegedProjectProvider
	projectMember                                  provider.ProjectMemberProvider
	privilegedProjectMemberProvider                provider.PrivilegedProjectMemberProvider
	memberMapper                                   provider.ProjectMemberMapper
	eventRecorderProvider                          provider.EventRecorderProvider
	clusterProviderGetter                          provider.ClusterProviderGetter
	seedsGetter                                    provider.SeedsGetter
	seedClientGetter                               provider.SeedClientGetter
	configGetter                                   provider.KubermaticConfigurationGetter
	addons                                         provider.AddonProviderGetter
	addonConfigProvider                            provider.AddonConfigProvider
	userInfoGetter                                 provider.UserInfoGetter
	settingsProvider                               provider.SettingsProvider
	adminProvider                                  provider.AdminProvider
	presetProvider                                 provider.PresetProvider
	admissionPluginProvider                        provider.AdmissionPluginsProvider
	settingsWatcher                                watcher.SettingsWatcher
	userWatcher                                    watcher.UserWatcher
	externalClusterProvider                        provider.ExternalClusterProvider
	privilegedExternalClusterProvider              provider.PrivilegedExternalClusterProvider
	featureGatesProvider                           provider.FeatureGatesProvider
	constraintTemplateProvider                     provider.ConstraintTemplateProvider
	defaultConstraintProvider                      provider.DefaultConstraintProvider
	constraintProviderGetter                       provider.ConstraintProviderGetter
	alertmanagerProviderGetter                     provider.AlertmanagerProviderGetter
	clusterTemplateProvider                        provider.ClusterTemplateProvider
	clusterTemplateInstanceProviderGetter          provider.ClusterTemplateInstanceProviderGetter
	ruleGroupProviderGetter                        provider.RuleGroupProviderGetter
	privilegedAllowedRegistryProvider              provider.PrivilegedAllowedRegistryProvider
	etcdBackupConfigProviderGetter                 provider.EtcdBackupConfigProviderGetter
	etcdRestoreProviderGetter                      provider.EtcdRestoreProviderGetter
	etcdBackupConfigProjectProviderGetter          provider.EtcdBackupConfigProjectProviderGetter
	etcdRestoreProjectProviderGetter               provider.EtcdRestoreProjectProviderGetter
	backupStorageProvider                          provider.BackupStorageProvider
	backupCredentialsProviderGetter                provider.BackupCredentialsProviderGetter
	privilegedMLAAdminSettingProviderGetter        provider.PrivilegedMLAAdminSettingProviderGetter
	seedProvider                                   provider.SeedProvider
	resourceQuotaProvider                          provider.ResourceQuotaProvider
	groupProjectBindingProvider                    provider.GroupProjectBindingProvider
	privilegedIPAMPoolProviderGetter               provider.PrivilegedIPAMPoolProviderGetter
	applicationDefinitionProvider                  provider.ApplicationDefinitionProvider
	privilegedOperatingSystemProfileProviderGetter provider.PrivilegedOperatingSystemProfileProviderGetter
	oidcIssuerVerifierProviderGetter               provider.OIDCIssuerVerifierGetter
	policyTemplateProvider                         provider.PolicyTemplateProvider
	policyBindingProvider                          provider.PolicyBindingProvider
}

func loadKubermaticConfiguration(filename string) (*kubermaticv1.KubermaticConfiguration, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	defer f.Close()

	config := &kubermaticv1.KubermaticConfiguration{}
	decoder := yaml.NewDecoder(f)
	decoder.KnownFields(true)

	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to parse file as YAML: %w", err)
	}

	defaulted, err := defaulting.DefaultConfiguration(config, zap.NewNop().Sugar())
	if err != nil {
		return nil, fmt.Errorf("failed to process: %w", err)
	}

	return defaulted, nil
}
