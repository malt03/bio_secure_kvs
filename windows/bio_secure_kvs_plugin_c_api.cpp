#include "include/bio_secure_kvs/bio_secure_kvs_plugin_c_api.h"

#include <flutter/plugin_registrar_windows.h>

#include "bio_secure_kvs_plugin.h"

void BioSecureKvsPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  bio_secure_kvs::BioSecureKvsPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
