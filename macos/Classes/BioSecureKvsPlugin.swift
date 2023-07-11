import Cocoa
import FlutterMacOS

public class BioSecureKvsPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "bio_secure_kvs", binaryMessenger: registrar.messenger)
    let instance = BioSecureKvsPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    let arguments = call.arguments as! [Any]
    let service = arguments[0] as! String
    let key = arguments[1] as! String

    do {
      switch call.method {
      case "get":
        if let data = try KeyChainAccessor.get(service: service, key: key) {
          result(FlutterStandardTypedData(bytes: data))
        } else {
          result(nil)
        }
      case "set":
        let data = arguments[2] as! FlutterStandardTypedData
        try KeyChainAccessor.set(service: service, key: key, data: data.data)
        result(nil)
      case "delete":
        result(try KeyChainAccessor.delete(service: service, key: key))
      default:
        result(FlutterMethodNotImplemented)
      }
    } catch {
      guard let error = error as? OSStatusError else {
        return result(FlutterError(code: "unknown error", message: error.localizedDescription, details: ["error": error]))
      }
      result(FlutterError(code: "os error", message: error.localizedDescription, details: nil))
    }
  }
}