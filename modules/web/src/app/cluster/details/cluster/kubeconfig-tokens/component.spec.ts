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

import {ComponentFixture, TestBed, waitForAsync} from '@angular/core/testing';
import {MatDialogModule} from '@angular/material/dialog';
import {BrowserModule} from '@angular/platform-browser';
import {NoopAnimationsModule} from '@angular/platform-browser/animations';
import {AppConfigService} from '@app/config.service';
import {AppConfigMockService} from '@test/services/app-config-mock';
import {NotificationMockService} from '@test/services/notification-mock';
import {fakeDigitaloceanCluster} from '@test/data/cluster';
import {fakeProject} from '@test/data/project';
import {KubeconfigTokenService} from '@core/services/kubeconfig-token';
import {NotificationService} from '@core/services/notification';
import {SharedModule} from '@shared/module';
import {of, throwError} from 'rxjs';
import {KubeconfigTokensComponent} from './component';

const fakeSettings = {
  defaultLifetime: '24h0m0s',
  maxLifetime: '168h0m0s',
  idleTimeout: '24h0m0s',
  maxActivePerUserPerCluster: 10,
};

const fakeTokens = [
  {
    id: '0123456789abcdef',
    clusterID: fakeDigitaloceanCluster().id,
    userID: 'user-1',
    label: 'laptop',
    issueTime: new Date(),
    expirationTime: new Date(),
    lastUsedTime: new Date(),
    state: 'Active',
  },
  {
    id: 'fedcba9876543210',
    clusterID: fakeDigitaloceanCluster().id,
    userID: 'user-1',
    label: '',
    issueTime: new Date(),
    expirationTime: new Date(),
    state: 'Disabled',
    reason: 'Expired',
  },
];

class KubeconfigTokenMockService {
  getSettings = jest.fn();
  list = jest.fn();
  updateLabel = jest.fn();
  revoke = jest.fn();
}

describe('KubeconfigTokensComponent', () => {
  let component: KubeconfigTokensComponent;
  let fixture: ComponentFixture<KubeconfigTokensComponent>;
  let tokenService: KubeconfigTokenMockService;

  beforeEach(waitForAsync(() => {
    tokenService = new KubeconfigTokenMockService();
    tokenService.getSettings.mockReturnValue(of(fakeSettings));
    tokenService.list.mockReturnValue(of(fakeTokens));

    TestBed.configureTestingModule({
      imports: [BrowserModule, NoopAnimationsModule, MatDialogModule, SharedModule],
      declarations: [KubeconfigTokensComponent],
      providers: [
        {provide: KubeconfigTokenService, useValue: tokenService},
        {provide: NotificationService, useClass: NotificationMockService},
        {provide: AppConfigService, useClass: AppConfigMockService},
      ],
      teardown: {destroyAfterEach: false},
    }).compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(KubeconfigTokensComponent);
    component = fixture.componentInstance;
    component.projectID = fakeProject().id;
    component.cluster = fakeDigitaloceanCluster();
  });

  it('should initialize with the settings and tokens', () => {
    fixture.detectChanges();

    expect(component.isEnabled).toBe(true);
    expect(component.isInitialized).toBe(true);
    expect(component.settings).toEqual(fakeSettings);
    expect(component.tokens).toEqual(fakeTokens);
  });

  it('should hide itself when the token endpoints are off', () => {
    tokenService.getSettings.mockReturnValue(throwError({status: 404}));
    fixture.detectChanges();

    expect(component.isInitialized).toBe(true);
    expect(component.isEnabled).toBe(false);
  });

  it('should revoke a token and refresh the list', () => {
    tokenService.revoke.mockReturnValue(of(null));
    fixture.detectChanges();

    component.revoke(fakeTokens[0]);
    expect(tokenService.revoke).toHaveBeenCalledWith(fakeProject().id, fakeDigitaloceanCluster().id, fakeTokens[0].id);
  });

  it('should explain an unknown state', () => {
    expect(component.getStateTooltip({...fakeTokens[0], state: ''})).toContain('not reported');
    expect(component.getStateTooltip(fakeTokens[0])).toContain('accepts');
    expect(component.getStateTooltip(fakeTokens[1])).toContain('Expired');
  });
});
