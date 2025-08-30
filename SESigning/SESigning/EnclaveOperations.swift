//
//  EnclaveOperations.swift
//  SESigning
//
//  Created by Thomas Karpiniec on 28/8/2025.
//

import Foundation
import Security
import CryptoKit

private let keyTag = "SESigning"
private let keyTagData = keyTag.data(using: .utf8)!

// Generate a new key, deleting the previous one if it exists
func generateNewKey() -> SecKey {
    // Delete existing key if present
    let deleteQuery: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: keyTagData
    ]
    SecItemDelete(deleteQuery as CFDictionary)
    
    // Create new key secured by Secure Enclave
    var error: Unmanaged<CFError>?
    let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .privateKeyUsage,
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

// Get public key binary representation
func getPublicKeyData(privateKey: SecKey? = nil) -> Data? {
    guard let key = privateKey else { return nil }
    guard let publicKey = SecKeyCopyPublicKey(key) else { return nil }
    var error: Unmanaged<CFError>?
    guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) else { return nil }
    return publicKeyData as Data
}

// Sign a message using the given key
func signMessage(_ message: String, privateKey: SecKey? = nil) -> Data? {
    let messageData = message.data(using: .utf8)!
    let key = privateKey ?? retrieveKey()
    guard let key = key else { return nil }
    
    var error: Unmanaged<CFError>?
    let signature = SecKeyCreateSignature(
        key,
        .ecdsaSignatureMessageX962SHA256,
        messageData as CFData,
        &error
    )
    
    return signature as? Data
}

// Verify signature against provided message and public key
func verifySignature(
    message: Data,
    publicKey: Data,
    signature: Data
) -> Bool {
    // Create public key from data
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
    
    // Verify signature (algorithm already does SHA256)
    let result = SecKeyVerifySignature(
        publicKeyRef,
        .ecdsaSignatureMessageX962SHA256,
        message as CFData,
        signature as CFData,
        &error
    )
    
    return result
}
