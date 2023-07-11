import 'bio_secure_kvs_platform_interface.dart';

class BioSecureKvs {
  const BioSecureKvs(this.service);

  final String service;

  Future<void> set(String key, List<int> value) {
    return BioSecureKvsPlatform.instance.set(service, key, value);
  }

  Future<List<int>?> get(String key) {
    return BioSecureKvsPlatform.instance.get(service, key);
  }

  Future<bool> delete(String key) {
    return BioSecureKvsPlatform.instance.delete(service, key);
  }
}
