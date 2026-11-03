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

import {HttpClient} from '@angular/common/http';
import {Injectable} from '@angular/core';
import {environment} from '@environments/environment';
import {KubeconfigToken, KubeconfigTokenSettings} from '@shared/entity/kubeconfig-token';
import {Observable} from 'rxjs';

@Injectable({
  providedIn: 'root',
})
export class KubeconfigTokenService {
  private readonly _restRoot = environment.newRestRoot;
  private readonly _location: string = window.location.protocol + '//' + window.location.host;

  constructor(private readonly _httpClient: HttpClient) {}

  /**
   * Returns the lifetime settings for new tokens of the cluster, or null when
   * per-cluster kubeconfig tokens are not enabled (the endpoint does not exist).
   */
  getSettings(projectID: string, clusterID: string): Observable<KubeconfigTokenSettings> {
    const url = `${this._restRoot}/projects/${projectID}/clusters/${clusterID}/kubeconfig/tokens/settings`;
    return this._httpClient.get<KubeconfigTokenSettings>(url);
  }

  list(projectID: string, clusterID: string): Observable<KubeconfigToken[]> {
    const url = `${this._restRoot}/projects/${projectID}/clusters/${clusterID}/kubeconfig/tokens`;
    return this._httpClient.get<KubeconfigToken[]>(url);
  }

  updateLabel(projectID: string, clusterID: string, tokenID: string, label: string): Observable<KubeconfigToken> {
    const url = `${this._restRoot}/projects/${projectID}/clusters/${clusterID}/kubeconfig/tokens/${tokenID}`;
    return this._httpClient.patch<KubeconfigToken>(url, {label} as KubeconfigTokenPatch);
  }

  revoke(projectID: string, clusterID: string, tokenID: string): Observable<void> {
    const url = `${this._restRoot}/projects/${projectID}/clusters/${clusterID}/kubeconfig/tokens/${tokenID}`;
    return this._httpClient.delete<void>(url);
  }

  /**
   * Returns the browser URL that starts the export flow: an OIDC login followed
   * by a one-time token and kubeconfig.
   */
  getExportURL(clusterID: string, lifetime?: string): string {
    const location = this._location.endsWith('/') ? this._location : `${this._location}/`;
    const restRoot = this._restRoot.startsWith('/') ? this._restRoot.slice(1) : this._restRoot;
    const query = lifetime ? `?lifetime=${encodeURIComponent(lifetime)}` : '';
    return `${location}${restRoot}/clusters/${clusterID}/kubeconfig/token${query}`;
  }

  listAdmin(clusterID?: string, userID?: string): Observable<KubeconfigToken[]> {
    const params = new URLSearchParams();
    if (clusterID) {
      params.set('cluster_id', clusterID);
    }
    if (userID) {
      params.set('user_id', userID);
    }
    const query = params.size > 0 ? `?${params.toString()}` : '';
    const url = `${this._restRoot}/admin/kubeconfig/tokens${query}`;
    return this._httpClient.get<KubeconfigToken[]>(url);
  }

  revokeAdmin(tokenID: string): Observable<void> {
    const url = `${this._restRoot}/admin/kubeconfig/tokens/${tokenID}`;
    return this._httpClient.delete<void>(url);
  }
}

interface KubeconfigTokenPatch {
  label: string;
}
