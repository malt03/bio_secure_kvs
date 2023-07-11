import 'package:flutter_test/flutter_test.dart';
import 'package:bio_secure_kvs/bio_secure_kvs.dart';
import 'package:bio_secure_kvs/bio_secure_kvs_platform_interface.dart';
import 'package:bio_secure_kvs/bio_secure_kvs_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockBioSecureKvsPlatform
    with MockPlatformInterfaceMixin
    implements BioSecureKvsPlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final BioSecureKvsPlatform initialPlatform = BioSecureKvsPlatform.instance;

  test('$MethodChannelBioSecureKvs is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelBioSecureKvs>());
  });

  test('getPlatformVersion', () async {
    BioSecureKvs bioSecureKvsPlugin = BioSecureKvs();
    MockBioSecureKvsPlatform fakePlatform = MockBioSecureKvsPlatform();
    BioSecureKvsPlatform.instance = fakePlatform;

    expect(await bioSecureKvsPlugin.getPlatformVersion(), '42');
  });
}
