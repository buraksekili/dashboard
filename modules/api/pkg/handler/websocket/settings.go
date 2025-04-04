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

package websocket

import (
	"context"
	"encoding/json"

	"github.com/gorilla/websocket"

	apiv2 "k8c.io/dashboard/v2/pkg/api/v2"
	"k8c.io/dashboard/v2/pkg/handler/v1/admin"
	"k8c.io/dashboard/v2/pkg/watcher"
	kubermaticv1 "k8c.io/kubermatic/sdk/v2/apis/kubermatic/v1"
	"k8c.io/kubermatic/v2/pkg/log"
)

func WriteSettings(ctx context.Context, providers watcher.Providers, ws *websocket.Conn) {
	// There can be a race here if the settings change between getting the initial data and setting up the subscription
	initialSettings, err := providers.SettingsProvider.GetGlobalSettings(ctx)
	if err != nil {
		log.Logger.Debug(err)
		return
	}

	initialResponse, err := json.Marshal(admin.ConvertCRDSettingsToAPISettingsSpec(&initialSettings.Spec))
	if err != nil {
		log.Logger.Debug(err)
		return
	}

	if err := ws.WriteMessage(websocket.TextMessage, initialResponse); err != nil {
		log.Logger.Debug(err)
		return
	}

	unSub := providers.SettingsWatcher.Subscribe(func(settings interface{}) {
		var response []byte
		if settings != nil {
			var externalSettings apiv2.GlobalSettings
			internalSettings, ok := settings.(*kubermaticv1.KubermaticSetting)
			if ok {
				externalSettings = admin.ConvertCRDSettingsToAPISettingsSpec(&internalSettings.Spec)
			} else {
				log.Logger.Debug("cannot convert settings: %v", settings)
			}

			response, err = json.Marshal(externalSettings)
			if err != nil {
				log.Logger.Debug(err)
				return
			}
		} else {
			// Explicitly set null response instead returning defaulted global settings structure.
			// It allows clients to distinct null response and default or empty global settings structure.
			response, err = json.Marshal(nil)
			if err != nil {
				log.Logger.Debug(err)
				return
			}
		}

		if err := ws.WriteMessage(websocket.TextMessage, response); err != nil {
			log.Logger.Debug(err)
			return
		}
	})

	ws.SetCloseHandler(func(code int, text string) error {
		unSub()
		return writeCloseMessage(ws, code)
	})
}
