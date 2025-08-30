//
//  ContentView.swift
//  SESigning
//
//  Created by Thomas Karpiniec on 28/8/2025.
//

import SwiftUI

struct ContentView: View {
    @State private var publicKey: String = ""
    @State private var message: String = ""
    @State private var signature: String = ""
    @State private var resultText: String = ""
    @FocusState private var isTextFieldFocused: Bool
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Button("Generate Key") {
                    generateKey()
                }
                .buttonStyle(.borderedProminent)
                .frame(maxWidth: .infinity)
                
                Text("Public key")
                    .font(.headline)
                TextEditor(text: $publicKey)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 100)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color.gray.opacity(0.3), lineWidth: 1)
                    )
                    .focused($isTextFieldFocused)
                
                Text("Message")
                    .font(.headline)
                TextEditor(text: $message)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 80)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color.gray.opacity(0.3), lineWidth: 1)
                    )
                    .focused($isTextFieldFocused)
                
                Button("Create signature") {
                    createSignature()
                }
                .buttonStyle(.borderedProminent)
                .frame(maxWidth: .infinity)
                
                Text("Signature")
                    .font(.headline)
                TextEditor(text: $signature)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 100)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color.gray.opacity(0.3), lineWidth: 1)
                    )
                    .focused($isTextFieldFocused)
                
                Button("Verify signature") {
                    verifySignature()
                }
                .buttonStyle(.borderedProminent)
                .frame(maxWidth: .infinity)
                
                Text(resultText)
                    .font(.body)
                    .foregroundColor(resultText.contains("Success") ? .green : 
                                   resultText.contains("Failed") ? .red : .primary)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.vertical, 8)
            }
            .padding()
        }
        .onTapGesture {
            isTextFieldFocused = false
        }
    }
    
    private func generateKey() {
        let newKey = generateNewKey()
        publicKey = getPublicKeyData(privateKey: newKey)?.toHexString() ?? ""
        signature = ""
        resultText = ""
    }
    
    private func createSignature() {
        guard !message.isEmpty else {
            resultText = "Please enter a message"
            return
        }
        var privateKey = retrieveKey()
        if privateKey == nil {
            privateKey = generateNewKey()
        }
        if let publicKeyData = getPublicKeyData(privateKey: privateKey) {
            publicKey = publicKeyData.toHexString()
        }
        if let signatureData = signMessage(message, privateKey: privateKey) {
            signature = signatureData.toHexString()
            resultText = ""
        } else {
            resultText = "Failed to create signature"
        }
    }
    
    private func verifySignature() {
        guard !message.isEmpty else {
            resultText = "Please enter a message"
            return
        }
        guard let publicKeyData = publicKey.fromHexString() else {
            resultText = "Invalid public key format"
            return
        }
        guard let signatureData = signature.fromHexString() else {
            resultText = "Invalid signature format"
            return
        }
        guard let messageData = message.data(using: .utf8) else {
            resultText = "Invalid message encoding"
            return
        }
        let isValid = SESigning.verifySignature(
            message: messageData,
            publicKey: publicKeyData,
            signature: signatureData
        )
        resultText = isValid ? "✅ Signature verification OK" : "❌ Signature verification failure"
    }
}

#Preview {
    ContentView()
}

// Hex conversion helpers

extension Data {
    func toHexString() -> String {
        return self.map { String(format: "%02x", $0) }.joined()
    }
}

extension String {
    func fromHexString() -> Data? {
        let hex = self.replacingOccurrences(of: " ", with: "")
                      .replacingOccurrences(of: "\n", with: "")
                      .replacingOccurrences(of: "\r", with: "")
        guard hex.count % 2 == 0 else { return nil }
        var data = Data()
        var index = hex.startIndex
        
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            if let byte = UInt8(hex[index..<nextIndex], radix: 16) {
                data.append(byte)
            } else {
                return nil
            }
            index = nextIndex
        }
        
        return data
    }
}
