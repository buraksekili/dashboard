// Copyright 2020 The Kubermatic Kubernetes Platform contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {Component, Input, OnDestroy, OnInit} from '@angular/core';
import {MatDialogRef} from '@angular/material/dialog';
import {GoogleAnalyticsService} from '@app/google-analytics.service';
import {ClusterService} from '@core/services/cluster';
import {MachineDeploymentService} from '@core/services/machine-deployment';
import {NotificationService} from '@core/services/notification';
import {ProjectService} from '@core/services/project';
import {Cluster, ClusterPatch} from '@shared/entity/cluster';
import {ExternalCluster, ExternalClusterPatch} from '@shared/entity/external-cluster';
import {Project} from '@shared/entity/project';
import {Observable, Subject} from 'rxjs';
import {map, take, takeUntil} from 'rxjs/operators';

@Component({
  selector: 'km-version-change-dialog',
  templateUrl: './template.html',
  styleUrls: ['./style.scss'],
  standalone: false,
})
export class VersionChangeDialogComponent implements OnInit, OnDestroy {
  @Input() cluster: Cluster | ExternalCluster;
  @Input() versions: string[] = [];
  @Input() hasVersionOptions = true;
  @Input() isClusterExternal = false;
  @Input() hasAvailableUpdates = false;

  selectedVersion: string;
  project: Project;
  isMachineDeploymentUpgradeEnabled = false;
  private _unsubscribe = new Subject<void>();
  protected nodesSupportDynamicKubeletConfig = '';

  constructor(
    private readonly _clusterService: ClusterService,
    private readonly _projectService: ProjectService,
    private readonly _machineDeploymentService: MachineDeploymentService,
    private readonly _dialogRef: MatDialogRef<VersionChangeDialogComponent>,
    private readonly _notificationService: NotificationService,
    private readonly _googleAnalyticsService: GoogleAnalyticsService
  ) {}

  ngOnInit(): void {
    if (this.versions.length > 0) {
      this.selectedVersion = this.versions[0];
    }

    this._projectService.selectedProject
      .pipe(takeUntil(this._unsubscribe))
      .subscribe(project => (this.project = project));
    this._googleAnalyticsService.emitEvent('clusterOverview', 'clusterVersionChangeDialogOpened');

    if (!this.isClusterExternal) {
      this._machineDeploymentService
        .list(this.cluster.id, this.project.id)
        .pipe(map(nodes => nodes.filter(node => node.spec.dynamicConfig)))
        .pipe(takeUntil(this._unsubscribe))
        .subscribe(nodes => {
          this.nodesSupportDynamicKubeletConfig = nodes.map(node => ` MD-${node.name}`).join(', ');
        });
    }
  }

  ngOnDestroy(): void {
    this._unsubscribe.next();
    this._unsubscribe.complete();
  }

  private _getPatch(): ClusterPatch | ExternalClusterPatch {
    const payload: ClusterPatch | ExternalClusterPatch = {
      spec: {
        version: this.selectedVersion,
      },
    };
    return payload;
  }

  private _patch(): Observable<Cluster | ExternalCluster> {
    return this.isClusterExternal
      ? this._clusterService.patchExternalCluster(this.project.id, this.cluster.id, this._getPatch())
      : this._clusterService.patch(this.project.id, this.cluster.id, this._getPatch());
  }

  getObservable(): Observable<Cluster | ExternalCluster> {
    return this._patch().pipe(take(1));
  }

  onNext(): void {
    this._notificationService.success(
      `Updating the ${this.cluster.name} cluster to the ${this.selectedVersion} version`
    );

    this._googleAnalyticsService.emitEvent('clusterOverview', 'clusterVersionChanged');

    if (!this.isClusterExternal && this.isMachineDeploymentUpgradeEnabled) {
      this.upgradeMachineDeployments();
    }
    this._dialogRef.close(true);
  }

  upgradeMachineDeployments(): void {
    this._clusterService
      .upgradeMachineDeployments(this.project.id, this.cluster.id, this.selectedVersion)
      .pipe(take(1))
      .subscribe(() => {
        this._notificationService.success(
          `Updating the machine deployments version to the ${this.selectedVersion} for the ${this.cluster.name} cluster`
        );
      });
  }
}
