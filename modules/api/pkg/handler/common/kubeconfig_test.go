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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeUserEmailToIDIgnoresCase(t *testing.T) {
	require.Equal(t, EncodeUserEmailToID("bob@acme.com"), EncodeUserEmailToID("Bob@ACME.com"))
	require.NotEqual(t, EncodeUserEmailToID("bob@acme.com"), EncodeUserEmailToID("alice@acme.com"))
}

func TestWebTerminalLegacyResourceNames(t *testing.T) {
	id := EncodeUserEmailToID("bob@acme.com")
	require.Equal(t, "kubeconfig-"+id, KubeconfigSecretName(id))
	require.Equal(t, "webterminal-oidc-"+id, WebTerminalOIDCSecretName(id))
}
