//
//  EnclaveOperations.swift
//  SETLS
//
//  Created by Thomas Karpiniec on 28/8/2025.
//

import Foundation
import Security
import CryptoKit

private let keyTag = "SETLS"
private let keyTagData = keyTag.data(using: .utf8)!

// Generate a new key, deleting the previous one if it exists
func generateNewKey() -> SecKey {
    // Delete existing key if present
    let deleteQuery: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: keyTagData
    ]
    SecItemDelete(deleteQuery as CFDictionary)
    
    var error: Unmanaged<CFError>?
    let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        // For this example app, require biometry
        [.privateKeyUsage, .biometryCurrentSet],
        &error
    )!
    
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: keyTagData,
            kSecAttrAccessControl as String: accessControl
        ]
    ]
    
    let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)!
    return privateKey
}

// Retrieve a reference to the secured private key if it exists
func retrieveKey() -> SecKey? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: keyTagData,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecReturnRef as String: true
    ]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    
    if status == errSecSuccess {
        return (item as! SecKey)
    }
    return nil
}

// Get public key
func getPublicKeyData(privateKey: SecKey? = nil) -> Data? {
    guard let key = privateKey else { return nil }
    guard let publicKey = SecKeyCopyPublicKey(key) else { return nil }
    var error: Unmanaged<CFError>?
    guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) else { return nil }
    return publicKeyData as Data
}

// Sign raw bytes using the given key
func signData(_ data: Data, privateKey: SecKey? = nil) -> Data? {
    let key = privateKey ?? retrieveKey()
    guard let key = key else { return nil }
    
    var error: Unmanaged<CFError>?
    let signature = SecKeyCreateSignature(
        key,
        .ecdsaSignatureMessageX962SHA256,
        data as CFData,
        &error
    )
    
    if let error = error {
        print("ERROR: SecKeyCreateSignature failed: \(error.takeRetainedValue())")
        return nil
    }
    return signature as? Data
}

// Sign some data - called from Rust
func signDataCallback(data: RustVec<UInt8>) -> RustVec<UInt8> {
    let dataArray = Array(data)
    let inputData = Data(dataArray)
    
    guard let signature = signData(inputData) else {
        return RustVec<UInt8>()
    }
    
    let rustVec = RustVec<UInt8>()
    for byte in signature {
        rustVec.push(value: byte)
    }
    return rustVec
}

// Return our public key - called from Rust
func getPublicKeyCallback() -> RustVec<UInt8> {
    guard let privateKey = retrieveKey() else {
        return RustVec<UInt8>()
    }
    guard let publicKeyData = getPublicKeyData(privateKey: privateKey) else {
        return RustVec<UInt8>()
    }    
    let rustVec = RustVec<UInt8>()
    for byte in publicKeyData {
        rustVec.push(value: byte)
    }
    return rustVec
}

// Verify signature against provided message and public key
func verifySignature(
    message: Data,
    publicKey: Data,
    signature: Data
) -> Bool {
    // Create public key from passed data
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits as String: 256
    ]
    
    var error: Unmanaged<CFError>?
    guard let publicKeyRef = SecKeyCreateWithData(
        publicKey as CFData,
        attributes as CFDictionary,
        &error
    ) else { return false }
    
    return SecKeyVerifySignature(
        publicKeyRef,
        .ecdsaSignatureMessageX962SHA256,
        message as CFData,
        signature as CFData,
        &error
    )
}
