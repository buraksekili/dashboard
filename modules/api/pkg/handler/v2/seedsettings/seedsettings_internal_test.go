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

package seedsettings

import (
	"context"
	"errors"
	"testing"

	apiv2 "k8c.io/dashboard/v2/pkg/api/v2"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"

	"k8s.io/apimachinery/pkg/api/equality"
)

// the shared test endpoint always provides a KubermaticConfiguration, so the endpoint is called directly
func TestGetSeedSettingsEndpointWithoutKubermaticConfiguration(t *testing.T) {
	seed := &kubermaticv1.Seed{
		Spec: kubermaticv1.SeedSpec{
			SeedDNSOverwrite: "eu",
			MLA:              &kubermaticv1.SeedMLASettings{UserClusterMLAEnabled: true},
			Metering:         &kubermaticv1.MeteringConfiguration{Enabled: true, StorageClassName: "fast", StorageSize: "100Gi"},
			KubeLB:           &kubermaticv1.KubeLBSeedSettings{EnableForAllDatacenters: true},
		},
	}
	seedsGetter := func() (map[string]*kubermaticv1.Seed, error) {
		return map[string]*kubermaticv1.Seed{"europe": seed}, nil
	}
	configGetter := func(context.Context) (*kubermaticv1.KubermaticConfiguration, error) {
		return nil, errors.New("no KubermaticConfiguration")
	}

	resp, err := GetSeedSettingsEndpoint(seedsGetter, configGetter)(context.Background(), getSeedSettingsReq{Name: "europe"})
	if err != nil {
		t.Fatalf("expected the endpoint to succeed, got %v", err)
	}

	expected := &apiv2.SeedSettings{
		MLA:              apiv2.MLA{UserClusterMLAEnabled: true},
		Metering:         kubermaticv1.MeteringConfiguration{Enabled: true, StorageClassName: "fast", StorageSize: "100Gi"},
		SeedDNSOverwrite: "eu",
		KubeLB:           &apiv2.KubeLBSeedSettingsAPI{EnableForAllDatacenters: true},
	}
	if !equality.Semantic.DeepEqual(resp, expected) {
		t.Errorf("expected %+v, got %+v", expected, resp)
	}
}
