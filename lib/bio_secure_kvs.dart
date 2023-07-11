import 'bio_secure_kvs_platform_interface.dart';

class BioSecureKvs {
  const BioSecureKvs();

  Future<void> set(String key, List<int> value) {
    return BioSecureKvsPlatform.instance.set(key, value);
  }

  Future<List<int>?> get(String key) {
    return BioSecureKvsPlatform.instance.get(key);
  }

  Future<bool> delete(String key) {
    return BioSecureKvsPlatform.instance.delete(key);
  }
}
