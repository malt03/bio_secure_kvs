import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'bio_secure_kvs_platform_interface.dart';

class MethodChannelBioSecureKvs extends BioSecureKvsPlatform {
  @visibleForTesting
  final methodChannel = const MethodChannel('bio_secure_kvs');

  @override
  set(key, value) {
    return methodChannel.invokeMethod<void>('set', [key, value]);
  }

  @override
  get(key) {
    return methodChannel.invokeMethod<List<int>>('get', [key]);
  }

  @override
  delete(key) async {
    final result = await methodChannel.invokeMethod<bool>('delete', [key]);
    return result!;
  }
}
