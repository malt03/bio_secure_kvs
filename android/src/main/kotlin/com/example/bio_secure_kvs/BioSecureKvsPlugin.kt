package com.example.bio_secure_kvs

import android.app.Activity
import android.content.Context
import android.util.Log
import androidx.annotation.NonNull
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

class BioSecureKvsPlugin: FlutterPlugin, MethodCallHandler, ActivityAware {
  private lateinit var channel : MethodChannel

  private lateinit var context: Context
  private lateinit var activity: FragmentActivity

  override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "bio_secure_kvs")
    context = flutterPluginBinding.applicationContext
  }

  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
    val arguments = call.arguments as ArrayList<Any>
    val service = arguments[0] as String
    val key = arguments[1] as String

    when (call.method) {
      "get" -> {
        KeyChainAccessor.get(context, activity, service, key) {
          result.success(it)
        }
      }
      "set" -> {
        val value = arguments[2] as ByteArray
        KeyChainAccessor.set(context, activity, service, key, value) {
          result.success(null)
        }
      }
      "delete" -> {
        result.success(KeyChainAccessor.delete(context, service, key))
      }
      else -> {
        result.notImplemented()
      }
    }
  }

  override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }

  override fun onAttachedToActivity(@NonNull activityPluginBinding: ActivityPluginBinding) {
    activity = activityPluginBinding.activity as FragmentActivity
    channel.setMethodCallHandler(this)
  }

  override fun onDetachedFromActivityForConfigChanges() {}

  override fun onReattachedToActivityForConfigChanges(@NonNull activityPluginBinding: ActivityPluginBinding) {
    activity = activityPluginBinding.activity as FragmentActivity
  }

  override fun onDetachedFromActivity() {}
}
