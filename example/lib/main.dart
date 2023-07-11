import 'dart:convert';

import 'package:flutter/material.dart';

import 'package:bio_secure_kvs/bio_secure_kvs.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  final _bioSecureKvsPlugin = const BioSecureKvs();

  final _key = 'com.malt03.bio_secure_kvs.dummy';

  @override
  Widget build(BuildContext context) {
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
                  } catch (e) {
                    print(e);
                  }
                },
                child: const Text('Set'),
              ),
              TextButton(
                onPressed: () async {
                  try {
                    final value = await _bioSecureKvsPlugin.get(_key);
                    if (value != null) {
                      print(utf8.decode(value));
                    } else {
                      print(null);
                    }
                  } catch (e) {
                    print(e);
                  }
                },
                child: const Text('Get'),
              ),
              TextButton(
                onPressed: () async {
                  try {
                    print(await _bioSecureKvsPlugin.delete(_key));
                  } catch (e) {
                    print(e);
                  }
                },
                child: const Text('Delete'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
