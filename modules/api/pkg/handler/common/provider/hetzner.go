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

package provider

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"github.com/hetznercloud/hcloud-go/hcloud"

	apiv1 "k8c.io/dashboard/v2/pkg/api/v1"
	handlercommon "k8c.io/dashboard/v2/pkg/handler/common"
	"k8c.io/dashboard/v2/pkg/handler/middleware"
	"k8c.io/dashboard/v2/pkg/handler/v1/common"
	"k8c.io/dashboard/v2/pkg/handler/v1/dc"
	"k8c.io/dashboard/v2/pkg/provider"
	"k8c.io/dashboard/v2/pkg/provider/cloud/hetzner"
	kubernetesprovider "k8c.io/dashboard/v2/pkg/provider/kubernetes"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	utilerrors "k8c.io/kubermatic/v2/pkg/util/errors"
)

var reStandardSize = regexp.MustCompile("(^cx|^cpx)")
var reDedicatedSize = regexp.MustCompile("(^ccx)")

func HetznerSizeWithClusterCredentialsEndpoint(ctx context.Context, userInfoGetter provider.UserInfoGetter, projectProvider provider.ProjectProvider, privilegedProjectProvider provider.PrivilegedProjectProvider, seedsGetter provider.SeedsGetter, settingsProvider provider.SettingsProvider, projectID, clusterID string) (interface{}, error) {
	clusterProvider := ctx.Value(middleware.ClusterProviderContextKey).(provider.ClusterProvider)

	cluster, err := handlercommon.GetCluster(ctx, projectProvider, privilegedProjectProvider, userInfoGetter, projectID, clusterID, &provider.ClusterGetOptions{CheckInitStatus: true})
	if err != nil {
		return nil, err
	}

	if cluster.Spec.Cloud.Hetzner == nil {
		return nil, utilerrors.NewNotFound("cloud spec for ", clusterID)
	}

	assertedClusterProvider, ok := clusterProvider.(*kubernetesprovider.ClusterProvider)
	if !ok {
		return nil, utilerrors.New(http.StatusInternalServerError, "failed to assert clusterProvider")
	}

	secretKeySelector := provider.SecretKeySelectorValueFuncFactory(ctx, assertedClusterProvider.GetSeedClusterAdminRuntimeClient())
	hetznerToken, err := hetzner.GetCredentialsForCluster(cluster.Spec.Cloud, secretKeySelector)
	if err != nil {
		return nil, err
	}

	settings, err := settingsProvider.GetGlobalSettings(ctx)
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}

	userInfo, err := userInfoGetter(ctx, "")
	if err != nil {
		return nil, common.KubernetesErrorToHTTPError(err)
	}
	datacenter, err := dc.GetDatacenter(userInfo, seedsGetter, cluster.Spec.Cloud.DatacenterName)
	if err != nil {
		return nil, utilerrors.New(http.StatusInternalServerError, err.Error())
	}

	if datacenter.Spec.Hetzner == nil {
		return nil, utilerrors.NewNotFound("cloud spec (dc) for ", clusterID)
	}

	filter := handlercommon.DetermineMachineFlavorFilter(datacenter.Spec.MachineFlavorFilter, settings.Spec.MachineDeploymentVMResourceQuota)
	return HetznerSize(ctx, filter, hetznerToken)
}

func HetznerSize(ctx context.Context, machineFilter kubermaticv1.MachineFlavorFilter, token string) (apiv1.HetznerSizeList, error) {
	client := hcloud.NewClient(hcloud.WithToken(token))

	listOptions := hcloud.ServerTypeListOpts{
		ListOpts: hcloud.ListOpts{
			Page:    1,
			PerPage: 1000,
		},
	}

	sizes, _, err := client.ServerType.List(ctx, listOptions)
	if err != nil {
		return apiv1.HetznerSizeList{}, fmt.Errorf("failed to list sizes: %w", err)
	}

	sizeList := apiv1.HetznerSizeList{}

	for _, size := range sizes {
		s := apiv1.HetznerSize{
			ID:          size.ID,
			Name:        size.Name,
			Description: size.Description,
			Cores:       size.Cores,
			Memory:      size.Memory,
			Disk:        size.Disk,
		}
		switch {
		case reStandardSize.MatchString(size.Name):
			sizeList.Standard = append(sizeList.Standard, s)
		case reDedicatedSize.MatchString(size.Name):
			sizeList.Dedicated = append(sizeList.Dedicated, s)
		}
	}

	return filterHetznerByQuota(sizeList, machineFilter), nil
}

func filterHetznerByQuota(instances apiv1.HetznerSizeList, machineFilter kubermaticv1.MachineFlavorFilter) apiv1.HetznerSizeList {
	filteredRecords := apiv1.HetznerSizeList{
		Standard:  []apiv1.HetznerSize{},
		Dedicated: []apiv1.HetznerSize{},
	}

	// Range over the records and apply all the filters to each record.
	// If the record passes all the filters, add it to the final slice.
	for _, r := range instances.Standard {
		keep := true

		if !handlercommon.FilterCPU(r.Cores, machineFilter.MinCPU, machineFilter.MaxCPU) {
			keep = false
		}
		if !handlercommon.FilterMemory(int(r.Memory), machineFilter.MinRAM, machineFilter.MaxRAM) {
			keep = false
		}

		if keep {
			filteredRecords.Standard = append(filteredRecords.Standard, r)
		}
	}
	for _, r := range instances.Dedicated {
		keep := true

		if !handlercommon.FilterCPU(r.Cores, machineFilter.MinCPU, machineFilter.MaxCPU) {
			keep = false
		}
		if !handlercommon.FilterMemory(int(r.Memory), machineFilter.MinRAM, machineFilter.MaxRAM) {
			keep = false
		}

		if keep {
			filteredRecords.Dedicated = append(filteredRecords.Dedicated, r)
		}
	}

	return filteredRecords
}
