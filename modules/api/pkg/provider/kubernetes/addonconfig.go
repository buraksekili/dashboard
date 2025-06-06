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

package kubernetes

import (
	"context"

	"k8c.io/dashboard/v2/pkg/provider"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// AddonConfigProvider struct that holds required components of the AddonConfigProvider.
type AddonConfigProvider struct {
	client ctrlruntimeclient.Client
}

var _ provider.AddonConfigProvider = &AddonConfigProvider{}

// NewAddonConfigProvider returns a new AddonConfigProvider.
func NewAddonConfigProvider(client ctrlruntimeclient.Client) *AddonConfigProvider {
	return &AddonConfigProvider{
		client: client,
	}
}

// Get addon configuration.
func (p *AddonConfigProvider) Get(ctx context.Context, addonName string) (*kubermaticv1.AddonConfig, error) {
	addonConfig := &kubermaticv1.AddonConfig{}
	if err := p.client.Get(ctx, ctrlruntimeclient.ObjectKey{Name: addonName}, addonConfig); err != nil {
		return nil, err
	}
	return addonConfig, nil
}

// List available addon configurations.
func (p *AddonConfigProvider) List(ctx context.Context) (*kubermaticv1.AddonConfigList, error) {
	addonConfigList := &kubermaticv1.AddonConfigList{}
	if err := p.client.List(ctx, addonConfigList); err != nil {
		return nil, err
	}
	return addonConfigList, nil
}
