import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'bio_secure_kvs_method_channel.dart';

abstract class BioSecureKvsPlatform extends PlatformInterface {
  BioSecureKvsPlatform() : super(token: _token);

  static final Object _token = Object();

  static BioSecureKvsPlatform _instance = MethodChannelBioSecureKvs();

  static BioSecureKvsPlatform get instance => _instance;

  static set instance(BioSecureKvsPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<void> set(String key, List<int> value) {
    throw UnimplementedError('set() has not been implemented.');
  }

  Future<List<int>?> get(String key) {
    throw UnimplementedError('get() has not been implemented.');
  }

  Future<bool> delete(String key) {
    throw UnimplementedError('delete() has not been implemented.');
  }
}
