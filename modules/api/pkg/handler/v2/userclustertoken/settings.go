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

// Package userclustertoken implements per-cluster kubeconfig tokens: the export flow that
// issues a token after a fresh OIDC login, and the API to list, label and revoke tokens.
// Tokens are stored as UserClusterTokenIssuance objects on the master; a master controller
// copies them to the seed, where the token webhook of each user cluster checks them.
package userclustertoken

import (
	"time"

	apiv2 "k8c.io/dashboard/v2/pkg/api/v2"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
)

// Defaults decided for the first release (implementation guide, section 0.2).
const (
	defaultLifetime                   = 24 * time.Hour
	defaultMaxLifetime                = 7 * 24 * time.Hour
	defaultIdleTimeout                = 24 * time.Hour
	defaultMaxActivePerUserPerCluster = 10

	// minLifetime keeps users from creating tokens that expire before they are copied
	// to the seed and used.
	minLifetime = 10 * time.Minute
)

// Settings are the lifetime rules for new tokens.
type Settings struct {
	DefaultLifetime            time.Duration
	MaxLifetime                time.Duration
	IdleTimeout                time.Duration
	MaxActivePerUserPerCluster int
}

// settingsFrom returns the token settings for the given KubermaticConfiguration.
// Zero values (a master that predates the fields, or a configuration not run through
// KKP defaulting) fall back to the decided defaults.
func settingsFrom(cfg *kubermaticv1.KubermaticConfiguration) Settings {
	settings := Settings{
		DefaultLifetime:            defaultLifetime,
		MaxLifetime:                defaultMaxLifetime,
		IdleTimeout:                defaultIdleTimeout,
		MaxActivePerUserPerCluster: defaultMaxActivePerUserPerCluster,
	}

	if cfg == nil {
		return settings
	}

	configured := cfg.Spec.UserClusterTokens
	if configured.DefaultLifetime.Duration > 0 {
		settings.DefaultLifetime = configured.DefaultLifetime.Duration
	}
	if configured.MaxLifetime.Duration > 0 {
		settings.MaxLifetime = configured.MaxLifetime.Duration
	}
	if configured.IdleTimeout.Duration > 0 {
		settings.IdleTimeout = configured.IdleTimeout.Duration
	}
	if configured.MaxActivePerUserPerCluster > 0 {
		settings.MaxActivePerUserPerCluster = int(configured.MaxActivePerUserPerCluster)
	}

	// a shorter maximum caps the default
	if settings.DefaultLifetime > settings.MaxLifetime {
		settings.DefaultLifetime = settings.MaxLifetime
	}

	return settings
}

func (s Settings) toAPI() apiv2.KubeconfigTokenSettings {
	return apiv2.KubeconfigTokenSettings{
		DefaultLifetime:            s.DefaultLifetime.String(),
		MaxLifetime:                s.MaxLifetime.String(),
		IdleTimeout:                s.IdleTimeout.String(),
		MaxActivePerUserPerCluster: s.MaxActivePerUserPerCluster,
	}
}
