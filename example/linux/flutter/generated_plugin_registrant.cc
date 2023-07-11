//
//  Generated file. Do not edit.
//

// clang-format off

#include "generated_plugin_registrant.h"

#include <bio_secure_kvs/bio_secure_kvs_plugin.h>

void fl_register_plugins(FlPluginRegistry* registry) {
  g_autoptr(FlPluginRegistrar) bio_secure_kvs_registrar =
      fl_plugin_registry_get_registrar_for_plugin(registry, "BioSecureKvsPlugin");
  bio_secure_kvs_plugin_register_with_registrar(bio_secure_kvs_registrar);
}
