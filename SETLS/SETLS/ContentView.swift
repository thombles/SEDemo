//
//  ContentView.swift
//  SETLS
//
//  Created by Thomas Karpiniec on 28/8/2025.
//

import SwiftUI

struct ContentView: View {
    @State private var identityStatus = "Unauthenticated"
    @State private var caServerUrl = "192.168.0.114:3000"
    @State private var targetDevice = ""
    @State private var messageToSend = ""
    @State private var lastReceivedMessage = "-"
    @State private var isWaitingForMessage = false
    @State private var isAuthenticating = false
    @State private var certificateChain = ""
    @FocusState private var isTextFieldFocused: Bool
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Identity status")
                    .font(.headline)
                Text(identityStatus)
                    .foregroundColor(identityStatusColor)
                
                Text("CA server")
                    .font(.headline)
                TextField("CA Server URL", text: $caServerUrl)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .focused($isTextFieldFocused)
                
                Button(isAuthenticating ? "Authenticating..." : "Authenticate") {
                    authenticate()
                }
                .buttonStyle(.borderedProminent)
                .frame(maxWidth: .infinity)
                .disabled(isAuthenticating)
                
                Text("Target device")
                    .font(.headline)
                TextField("hostname or IP", text: $targetDevice)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .focused($isTextFieldFocused)
                
                Text("Message to send")
                    .font(.headline)
                TextField("Enter message", text: $messageToSend)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .focused($isTextFieldFocused)
                
                Button("Connect and Send") {
                    connectAndSend()
                }
                .buttonStyle(.borderedProminent)
                .frame(maxWidth: .infinity)
                .disabled(certificateChain.isEmpty || targetDevice.isEmpty || messageToSend.isEmpty)
                
                Text("Last received message")
                    .font(.headline)
                Text(lastReceivedMessage)
                    .font(.body)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.vertical, 8)
                
                Button(isWaitingForMessage ? "Waiting for sender..." : "Wait for message") {
                    waitForMessage()
                }
                .buttonStyle(.borderedProminent)
                .frame(maxWidth: .infinity)
                .disabled(certificateChain.isEmpty || isWaitingForMessage)
            }
            .padding()
        }
        .onTapGesture {
            isTextFieldFocused = false
        }
    }
    
    private var identityStatusColor: Color {
        if identityStatus.contains("✅") {
            return .green
        } else if identityStatus.contains("❌") {
            return .red
        } else {
            return .primary
        }
    }
    
    private func authenticate() {
        Task {
            await performAuthentication()
        }
    }
    
    @MainActor
    private func performAuthentication() async {
        isAuthenticating = true
        
        // First create the private key using Swift Secure Enclave
        let _ = generateNewKey()
        
        // Then create CSR and get certificate
        let result = await get_certificate(caServerUrl)
        let resultString = result.toString()
        
        if !resultString.isEmpty {
            certificateChain = resultString
            identityStatus = "✅ Certificate retrieved"
        } else {
            identityStatus = "❌ Certificate retrieval failed"
        }
        
        isAuthenticating = false
    }
    
    private func connectAndSend() {
        Task {
            let messageWithNewline = messageToSend + "\n"
            let peer = targetDevice + ":4000"
            let messageData = messageWithNewline.data(using: .utf8) ?? Data()
            
            let rustVec = RustVec<UInt8>()
            for byte in messageData {
                rustVec.push(value: byte)
            }
            await send_message(certificateChain, peer, rustVec)
        }
    }
    
    private func waitForMessage() {
        Task {
            await performWaitForMessage()
        }
    }
    
    @MainActor
    private func performWaitForMessage() async {
        isWaitingForMessage = true
        
        // Listen for a message on port 4000
        let receivedMessage = await listen_for_message(certificateChain, 4000)
        let receivedString = receivedMessage.toString()
        
        if !receivedString.isEmpty {
            // Strip newline if present
            lastReceivedMessage = receivedString.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        } else {
            lastReceivedMessage = "-"
        }
        
        isWaitingForMessage = false
    }
}

#Preview {
    ContentView()
}
