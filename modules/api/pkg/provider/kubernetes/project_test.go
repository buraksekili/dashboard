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

package kubernetes_test

import (
	"context"
	"testing"

	"github.com/go-test/deep"

	"k8c.io/dashboard/v2/pkg/provider"
	"k8c.io/dashboard/v2/pkg/provider/kubernetes"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/test/fake"

	"k8s.io/apimachinery/pkg/api/equality"
	restclient "k8s.io/client-go/rest"
	ctrlruntimeclient "sigs.k8s.io/controller-runtime/pkg/client"
)

func TestListProjects(t *testing.T) {
	n1Project := genProject("n1", kubermaticv1.ProjectActive, defaultCreationTimestamp())
	n2Project := genProject("n2", kubermaticv1.ProjectActive, defaultCreationTimestamp())

	anotherN1Project := genProject("n3", kubermaticv1.ProjectActive, defaultCreationTimestamp())
	anotherN1Project.Spec.Name = "n1"

	// test data
	testcases := []struct {
		name             string
		existingProjects []*kubermaticv1.Project
		listOptions      *provider.ProjectListOptions
		expectedProjects []*kubermaticv1.Project
	}{
		{
			name:             "scenario 1: list all projects",
			listOptions:      nil,
			existingProjects: []*kubermaticv1.Project{n1Project, n2Project},
			expectedProjects: []*kubermaticv1.Project{n1Project, n2Project},
		},

		{
			name:             "scenario 2: list a project with a given name",
			listOptions:      &provider.ProjectListOptions{ProjectName: "n1"},
			existingProjects: []*kubermaticv1.Project{n1Project, n2Project},
			expectedProjects: []*kubermaticv1.Project{n1Project},
		},

		{
			name:             "scenario 3: list a projects with a given name",
			listOptions:      &provider.ProjectListOptions{ProjectName: "n1"},
			existingProjects: []*kubermaticv1.Project{n1Project, anotherN1Project, n2Project},
			expectedProjects: []*kubermaticv1.Project{n1Project, anotherN1Project},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			kubermaticObjects := []ctrlruntimeclient.Object{}
			for _, binding := range tc.existingProjects {
				kubermaticObjects = append(kubermaticObjects, binding)
			}
			fakeClient := fake.
				NewClientBuilder().
				WithObjects(kubermaticObjects...).
				Build()

			fakeImpersonationClient := func(impCfg restclient.ImpersonationConfig) (ctrlruntimeclient.Client, error) {
				return fakeClient, nil
			}

			// act
			target, err := kubernetes.NewProjectProvider(fakeImpersonationClient, fakeClient)
			if err != nil {
				t.Fatal(err)
			}
			result, err := target.List(context.Background(), tc.listOptions)

			// validate
			if err != nil {
				t.Fatal(err)
			}
			if len(tc.expectedProjects) != len(result) {
				t.Fatalf("expected to get %d projects, but got %d", len(tc.expectedProjects), len(result))
			}
			for _, returnedProject := range result {
				returnedProject.ResourceVersion = ""
				bindingFound := false
				for _, expectedProject := range tc.expectedProjects {
					expectedProject.ResourceVersion = ""
					if diff := deep.Equal(returnedProject, expectedProject); diff == nil {
						bindingFound = true
						break
					}
				}
				if !bindingFound {
					t.Fatalf("returned project was not found on the list of expected ones, binding = %#v", returnedProject)
				}
			}
		})
	}
}

func TestGetUnsecuredProjects(t *testing.T) {
	n1Project := genProject("n1", kubermaticv1.ProjectInactive, defaultCreationTimestamp())
	n2Project := genProject("n2", kubermaticv1.ProjectActive, defaultCreationTimestamp())

	// test data
	testcases := []struct {
		name             string
		projectName      string
		existingProjects []*kubermaticv1.Project
		getOptions       *provider.ProjectGetOptions
		expectedProject  *kubermaticv1.Project
		expectedError    string
	}{
		{
			name:             "scenario 1: get inactive project",
			projectName:      "n1-ID",
			getOptions:       &provider.ProjectGetOptions{IncludeUninitialized: true},
			expectedError:    "",
			existingProjects: []*kubermaticv1.Project{n1Project, n2Project},
			expectedProject:  genProject("n1", kubermaticv1.ProjectInactive, defaultCreationTimestamp()),
		},
		{
			name:             "scenario 2: get only active project",
			projectName:      "n1-ID",
			getOptions:       &provider.ProjectGetOptions{IncludeUninitialized: false},
			expectedError:    "Project is not initialized yet",
			existingProjects: []*kubermaticv1.Project{n1Project, n2Project},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			kubermaticObjects := []ctrlruntimeclient.Object{}
			for _, binding := range tc.existingProjects {
				kubermaticObjects = append(kubermaticObjects, binding)
			}

			fakeClient := fake.
				NewClientBuilder().
				WithObjects(kubermaticObjects...).
				Build()

			// act
			target, err := kubernetes.NewPrivilegedProjectProvider(fakeClient)
			if err != nil {
				t.Fatal(err)
			}
			result, err := target.GetUnsecured(context.Background(), tc.projectName, tc.getOptions)

			if len(tc.expectedError) == 0 {
				// validate
				if err != nil {
					t.Fatal(err)
				}

				tc.expectedProject.ResourceVersion = result.ResourceVersion

				if !equality.Semantic.DeepEqual(result, tc.expectedProject) {
					t.Fatalf("expected project: %v got: %v", tc.expectedProject, result)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error message")
				}
				if err.Error() != tc.expectedError {
					t.Fatalf("expected error message: %s got: %s", tc.expectedError, err.Error())
				}
			}
		})
	}
}
