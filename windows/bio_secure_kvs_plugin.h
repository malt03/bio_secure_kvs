#ifndef FLUTTER_PLUGIN_BIO_SECURE_KVS_PLUGIN_H_
#define FLUTTER_PLUGIN_BIO_SECURE_KVS_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

namespace bio_secure_kvs {

class BioSecureKvsPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  BioSecureKvsPlugin();

  virtual ~BioSecureKvsPlugin();

  // Disallow copy and assign.
  BioSecureKvsPlugin(const BioSecureKvsPlugin&) = delete;
  BioSecureKvsPlugin& operator=(const BioSecureKvsPlugin&) = delete;

  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace bio_secure_kvs

#endif  // FLUTTER_PLUGIN_BIO_SECURE_KVS_PLUGIN_H_
