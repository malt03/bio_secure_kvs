import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'bio_secure_kvs_platform_interface.dart';

class MethodChannelBioSecureKvs extends BioSecureKvsPlatform {
  @visibleForTesting
  final methodChannel = const MethodChannel('bio_secure_kvs');

  @override
  set(service, key, value) {
    return methodChannel.invokeMethod<void>('set', [service, key, value]);
  }

  @override
  get(service, key) {
    return methodChannel.invokeMethod<List<int>>('get', [service, key]);
  }

  @override
  delete(service, key) async {
    final result = await methodChannel.invokeMethod<bool>('delete', [service, key]);
    return result!;
  }
}
