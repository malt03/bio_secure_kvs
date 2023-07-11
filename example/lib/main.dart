import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_hooks/flutter_hooks.dart';

import 'package:bio_secure_kvs/bio_secure_kvs.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends HookWidget {
  const MyApp({super.key});

  final _bioSecureKvsPlugin = const BioSecureKvs("com.malt03.bio_secure_kvs");

  final _key = 'dummy-key';

  @override
  Widget build(BuildContext context) {
    final message = useState<String?>(null);

    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Plugin example app'),
        ),
        body: Center(
          child: Column(
            children: [
              TextButton(
                onPressed: () async {
                  try {
                    await _bioSecureKvsPlugin.set(_key, utf8.encode('dummy value'));
                    message.value = "Set; key: $_key, value: dummy value";
                  } catch (e) {
                    message.value = "Set Error: $e";
                  }
                },
                child: const Text('Set'),
              ),
              TextButton(
                onPressed: () async {
                  try {
                    final value = await _bioSecureKvsPlugin.get(_key);
                    if (value != null) {
                      message.value = "Get; key: $_key, value: ${utf8.decode(value)}";
                    } else {
                      message.value = "Get; key: $_key, value: not found";
                    }
                  } catch (e) {
                    message.value = "Get Error: $e";
                  }
                },
                child: const Text('Get'),
              ),
              TextButton(
                onPressed: () async {
                  try {
                    if (await _bioSecureKvsPlugin.delete(_key)) {
                      message.value = "Delete; key: $_key";
                    } else {
                      message.value = "Delete; key: $_key, not found";
                    }
                  } catch (e) {
                    message.value = "Delete Error: $e";
                  }
                },
                child: const Text('Delete'),
              ),
              Text(message.value ?? ''),
            ],
          ),
        ),
      ),
    );
  }
}
