// Copyright 2026 The Kubermatic Kubernetes Platform contributors.
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

import {Component, Input, OnChanges, OnDestroy, OnInit, ChangeDetectionStrategy} from '@angular/core';
import {MatDialog} from '@angular/material/dialog';
import {MatTableDataSource} from '@angular/material/table';
import {KubeconfigTokenService} from '@core/services/kubeconfig-token';
import {NotificationService} from '@core/services/notification';
import {Cluster} from '@shared/entity/cluster';
import {KubeconfigToken, KubeconfigTokenSettings} from '@shared/entity/kubeconfig-token';
import _ from 'lodash';
import {Subject, of} from 'rxjs';
import {catchError, filter, switchMap, take, takeUntil} from 'rxjs/operators';
import {EditTokenLabelDialogComponent} from './edit-label/component';

enum Column {
  State = 'state',
  Label = 'label',
  Created = 'created',
  Expires = 'expires',
  LastUsed = 'lastUsed',
  Actions = 'actions',
}

@Component({
  selector: 'km-kubeconfig-tokens',
  templateUrl: './template.html',
  changeDetection: ChangeDetectionStrategy.Eager,
  standalone: false,
})
export class KubeconfigTokensComponent implements OnInit, OnChanges, OnDestroy {
  readonly Column = Column;
  readonly displayedColumns: string[] = Object.values(Column);
  tokens: KubeconfigToken[] = [];
  dataSource = new MatTableDataSource<KubeconfigToken>();
  isEnabled = false;
  isInitialized = false;
  settings: KubeconfigTokenSettings;

  @Input() cluster: Cluster;
  @Input() projectID: string;

  private readonly _unsubscribe = new Subject<void>();
  private readonly _onTokensChange = new Subject<void>();

  constructor(
    private readonly _tokenService: KubeconfigTokenService,
    private readonly _matDialog: MatDialog,
    private readonly _notificationService: NotificationService
  ) {}

  ngOnInit(): void {
    this.dataSource.data = this.tokens;

    // a 404 means per-cluster kubeconfig tokens are not enabled; hide the card
    this._tokenService
      .getSettings(this.projectID, this.cluster.id)
      .pipe(
        take(1),
        catchError(() => of(null))
      )
      .subscribe(settings => {
        this.isEnabled = !!settings;
        this.settings = settings;
        this.isInitialized = true;
      });

    this._onTokensChange
      .pipe(
        switchMap(() => this._tokenService.list(this.projectID, this.cluster.id)),
        takeUntil(this._unsubscribe)
      )
      .subscribe(tokens => {
        this.tokens = tokens ?? [];
        this.dataSource.data = this.tokens;
      });

    this._onTokensChange.next();
  }

  ngOnChanges(): void {
    if (this.cluster?.id && this.projectID) {
      this._onTokensChange.next();
    }
  }

  ngOnDestroy(): void {
    this._unsubscribe.next();
    this._unsubscribe.complete();
  }

  editLabel(token: KubeconfigToken): void {
    const dialog = this._matDialog.open(EditTokenLabelDialogComponent);
    dialog.componentInstance.token = token;
    dialog
      .afterClosed()
      .pipe(
        take(1),
        filter(label => _.isString(label)),
        switchMap(label => this._tokenService.updateLabel(this.projectID, this.cluster.id, token.id, label as string))
      )
      .subscribe(() => {
        this._notificationService.success(`Updated the label of token ${token.id}`);
        this._onTokensChange.next();
      });
  }

  revoke(token: KubeconfigToken): void {
    this._tokenService
      .revoke(this.projectID, this.cluster.id, token.id)
      .pipe(take(1))
      .subscribe(() => {
        this._notificationService.success(`Revoked token ${token.id}`);
        this._onTokensChange.next();
      });
  }

  getStateTooltip(token: KubeconfigToken): string {
    if (!token.state) {
      return 'The cluster has not reported the state of this token yet';
    }
    if (token.state === 'Active') {
      return 'The cluster accepts this token';
    }
    return `The cluster rejects this token: ${token.reason ?? token.state}`;
  }
}
