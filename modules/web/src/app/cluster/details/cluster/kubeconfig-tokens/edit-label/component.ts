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

import {Component, Input, ChangeDetectionStrategy} from '@angular/core';
import {MatDialogRef} from '@angular/material/dialog';
import {KubeconfigToken} from '@shared/entity/kubeconfig-token';

// mirrors the CRD limit on the token label
const MAX_LABEL_LENGTH = 128;

@Component({
  selector: 'km-edit-token-label',
  templateUrl: './template.html',
  changeDetection: ChangeDetectionStrategy.Eager,
  standalone: false,
})
export class EditTokenLabelDialogComponent {
  readonly maxLabelLength = MAX_LABEL_LENGTH;

  @Input() token: KubeconfigToken;

  label = '';

  constructor(private readonly _matDialogRef: MatDialogRef<EditTokenLabelDialogComponent>) {}

  ngOnInit(): void {
    this.label = this.token?.label ?? '';
  }

  get isValid(): boolean {
    return this.label.trim().length <= MAX_LABEL_LENGTH;
  }

  save(): void {
    if (this.isValid) {
      this._matDialogRef.close(this.label.trim());
    }
  }
}
