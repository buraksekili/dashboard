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
	"fmt"

	"k8c.io/dashboard/v2/pkg/provider"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/util/restmapper"

	"k8s.io/apimachinery/pkg/types"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// ConstraintTemplateProvider struct that holds required components in order manage constraint templates.
type ConstraintTemplateProvider struct {
	// createSeedImpersonatedClient is used as a ground for impersonation
	createMasterImpersonatedClient ImpersonationClient
	clientPrivileged               ctrlruntimeclient.Client
	restMapperCache                *restmapper.Cache
}

var _ provider.ConstraintTemplateProvider = &ConstraintTemplateProvider{}

// NewConstraintTemplateProvider returns a constraint template provider.
func NewConstraintTemplateProvider(createMasterImpersonatedClient ImpersonationClient, client ctrlruntimeclient.Client) (*ConstraintTemplateProvider, error) {
	return &ConstraintTemplateProvider{
		createMasterImpersonatedClient: createMasterImpersonatedClient,
		clientPrivileged:               client,
		restMapperCache:                restmapper.New(),
	}, nil
}

// List gets all constraint templates.
func (p *ConstraintTemplateProvider) List(ctx context.Context) (*kubermaticv1.ConstraintTemplateList, error) {
	constraintTemplates := &kubermaticv1.ConstraintTemplateList{}
	if err := p.clientPrivileged.List(ctx, constraintTemplates); err != nil {
		return nil, fmt.Errorf("failed to list constraint templates: %w", err)
	}

	return constraintTemplates, nil
}

// Get gets a constraint template.
func (p *ConstraintTemplateProvider) Get(ctx context.Context, name string) (*kubermaticv1.ConstraintTemplate, error) {
	constraintTemplate := &kubermaticv1.ConstraintTemplate{}
	if err := p.clientPrivileged.Get(ctx, types.NamespacedName{Name: name}, constraintTemplate); err != nil {
		return nil, err
	}

	return constraintTemplate, nil
}

// Create creates a constraint template.
func (p *ConstraintTemplateProvider) Create(ctx context.Context, ct *kubermaticv1.ConstraintTemplate) (*kubermaticv1.ConstraintTemplate, error) {
	if err := p.clientPrivileged.Create(ctx, ct); err != nil {
		return nil, err
	}

	return ct, nil
}

// Update updates a constraint template.
func (p *ConstraintTemplateProvider) Update(ctx context.Context, ct *kubermaticv1.ConstraintTemplate) (*kubermaticv1.ConstraintTemplate, error) {
	if err := p.clientPrivileged.Update(ctx, ct); err != nil {
		return nil, err
	}

	return ct, nil
}

// Delete deletes a constraint template.
func (p *ConstraintTemplateProvider) Delete(ctx context.Context, ct *kubermaticv1.ConstraintTemplate) error {
	return p.clientPrivileged.Delete(ctx, ct)
}
