// Keymaster, access Keychain secrets guarded by TouchID
//
import Foundation
import LocalAuthentication

let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics

func setPassword(key: String, password: String) -> Bool {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecValueData as String: password.data(using: .utf8)!
  ]

  let status = SecItemAdd(query as CFDictionary, nil)
  return status == errSecSuccess
}

func updatePassword(key: String, password: String) -> Bool {
  // First check if the item exists
  let checkQuery: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecMatchLimit as String: kSecMatchLimitOne
  ]
  
  let checkStatus = SecItemCopyMatching(checkQuery as CFDictionary, nil)
  
  // If item doesn't exist, return false
  if checkStatus != errSecSuccess {
    return false
  }
  
  // Item exists, now update it
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key
  ]
  
  let attributesToUpdate: [String: Any] = [
    kSecValueData as String: password.data(using: .utf8)!
  ]
  
  let updateStatus = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
  return updateStatus == errSecSuccess
}

func deletePassword(key: String) -> Bool {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecMatchLimit as String: kSecMatchLimitOne
  ]
  let status = SecItemDelete(query as CFDictionary)
  return status == errSecSuccess
}

func getPassword(key: String) -> String? {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecReturnData as String: true
  ]
  var item: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &item)

  guard status == errSecSuccess,
    let passwordData = item as? Data,
    let password = String(data: passwordData, encoding: .utf8)
  else { return nil }

  return password
}

func usage() {
  print("keymaster [get|set|update|delete|get-many] [key] [secret]")
  print("  get-many: keymaster get-many key1 key2 key3...")
  print("  update: keymaster update existing-key <new-key> (fails if key doesn't exist)")
}


func main() {
  let inputArgs: [String] = Array(CommandLine.arguments.dropFirst())
  if (inputArgs.count < 1) {
    usage()
    exit(EXIT_FAILURE)
  }
  
  let action = inputArgs[0]
  
  // Validate arguments based on action
  if (action == "get-many" && inputArgs.count < 2) {
    print("Error: get-many requires at least one key")
    usage()
    exit(EXIT_FAILURE)
  } else if (action != "get-many" && (inputArgs.count < 2 || inputArgs.count > 3)) {
    usage()
    exit(EXIT_FAILURE) 
  }
  
  let key = inputArgs.count > 1 ? inputArgs[1] : ""
  var secret = ""
  if ((action == "set" || action == "update") && inputArgs.count == 3) {
    secret = inputArgs[2]
  }

  let context = LAContext()
  context.touchIDAuthenticationAllowableReuseDuration = 3

  var error: NSError?
  guard context.canEvaluatePolicy(policy, error: &error) else {
    print("This Mac doesn't support deviceOwnerAuthenticationWithBiometrics")
    exit(EXIT_FAILURE)
  }

  if (action == "set") {
    context.evaluatePolicy(policy, localizedReason: "set to your password") { success, error in
      if success {
        guard setPassword(key: key, password: secret) else {
          print("Error setting password")
          exit(EXIT_FAILURE)
        }
        print("Key \(key) has been successfully set in the keychain")
        exit(EXIT_SUCCESS)
      } else {
        print("Authentication failed or was canceled: \(error?.localizedDescription ?? "Unknown error")")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }

  if (action == "update") {
    context.evaluatePolicy(policy, localizedReason: "update your password") { success, error in
      if success && error == nil {
        guard updatePassword(key: key, password: secret) else {
          print("Error: Key '\(key)' does not exist or failed to update")
          print("Use 'set' command to create a new key or check if the key exists")
          exit(EXIT_FAILURE)
        }
        print("Key \(key) has been successfully updated in the keychain")
        exit(EXIT_SUCCESS)
      } else {
        let errorDescription = error?.localizedDescription ?? "Unknown error"
        print("Error \(errorDescription)")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }

  if (action == "update") {
    context.evaluatePolicy(policy, localizedReason: "update your password") { success, error in
      if success && error == nil {
        guard updatePassword(key: key, password: secret) else {
          print("Error: Key '\(key)' does not exist or failed to update")
          print("Use 'set' command to create a new key or check if the key exists")
          exit(EXIT_FAILURE)
        }
        print("Key \(key) has been successfully updated in the keychain")
        exit(EXIT_SUCCESS)
      } else {
        let errorDescription = error?.localizedDescription ?? "Unknown error"
        print("Error \(errorDescription)")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }

  if (action == "get") {
    context.evaluatePolicy(policy, localizedReason: "access to your password") { success, error in
      if success {
        guard let password = getPassword(key: key) else {
          print("Error getting password")
          exit(EXIT_FAILURE)
        }
        print(password)
        exit(EXIT_SUCCESS)
      } else {
        print("Authentication failed or was canceled: \(error?.localizedDescription ?? "Unknown error")")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }

  if (action == "get-many") {
    let keys = Array(inputArgs.dropFirst()) // Get all keys after "get-many"
    context.evaluatePolicy(policy, localizedReason: "access to your passwords") { success, error in
      if success && error == nil {
        var allFound = true
        var results: [String] = []
        
        for key in keys {
          if let password = getPassword(key: key) {
            results.append("\(key)=\(password)")
          } else {
            print("Error getting password for key: \(key)")
            allFound = false
            break
          }
        }
        
        if allFound {
          for result in results {
            print(result)
          }
          exit(EXIT_SUCCESS)
        } else {
          exit(EXIT_FAILURE)
        }
      } else {
        let errorDescription = error?.localizedDescription ?? "Unknown error"
        print("Error \(errorDescription)")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }

  if (action == "get-many") {
    let keys = Array(inputArgs.dropFirst()) // Get all keys after "get-many"
    context.evaluatePolicy(policy, localizedReason: "access to your passwords") { success, error in
      if success && error == nil {
        var allFound = true
        var results: [String] = []
        
        for key in keys {
          if let password = getPassword(key: key) {
            results.append("\(key)=\(password)")
          } else {
            print("Error getting password for key: \(key)")
            allFound = false
            break
          }
        }
        
        if allFound {
          for result in results {
            print(result)
          }
          exit(EXIT_SUCCESS)
        } else {
          exit(EXIT_FAILURE)
        }
      } else {
        let errorDescription = error?.localizedDescription ?? "Unknown error"
        print("Error \(errorDescription)")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }

  if (action == "delete") {
    context.evaluatePolicy(policy, localizedReason: "delete your password") { success, error in
      if success {
        guard deletePassword(key: key) else {
          print("Error deleting password")
          exit(EXIT_FAILURE)
        }
        print("Key \(key) has been successfully deleted from the keychain")
        exit(EXIT_SUCCESS)
      } else {
        print("Authentication failed or was canceled: \(error?.localizedDescription ?? "Unknown error")")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }
}

main()
