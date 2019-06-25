//
//  EncryptedAPIManager.swift
//  EncryptedAPIManager
//
//  Created by Arunprasat Selvaraj on 24/06/2019.
//  Copyright © 2019 Arunprasat Selvaraj. All rights reserved.
//

import Foundation
import CommonCrypto
import Security
import SystemConfiguration

public protocol Encrypter {
    
    func encrypt(_ data: Data) throws -> Data
    func decrypt(_ encrypted: Data) throws -> Data
}

public class APIHandler {
    
    public var error: Error?
    public var response: URLResponse?
    public var data: Data?
    
    public init(error: Error?, response: URLResponse?, data: Data?) {
        
        self.data = data
        self.error = error
        self.response = response
    }
}

public class EncryptedAPIManager {
    
    //Variables
    private var key: Data
    private let ivSize: Int  = kCCBlockSizeAES128
    private let options: CCOptions = CCOptions(kCCOptionPKCS7Padding)
    
    //Init
    public init(key: String) throws {
        guard !(key.isEmpty) else {
            throw Error.invalidKeySize
        }
        
        self.key = key.data(using: .utf8)!
    }
    
    public enum Error: Swift.Error {
        
        case invalidKeySize
        case generateRandomIVFailed
        case encryptionFailed
        case decryptionFailed
    }
}

//MARK: API & Encrption & Decryption call functions
extension EncryptedAPIManager {
    
    //To check network connection
    public func isConnectedToNetwork() -> Bool {
        
        var zeroAddress = sockaddr_in()
        zeroAddress.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        zeroAddress.sin_family = sa_family_t(AF_INET)
        
        guard let defaultRouteReachability = withUnsafePointer(to: &zeroAddress, {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                SCNetworkReachabilityCreateWithAddress(nil, $0)
            }
        }) else {
            return false
        }
        
        var flags: SCNetworkReachabilityFlags = []
        if !SCNetworkReachabilityGetFlags(defaultRouteReachability, &flags) {
            return false
        }
        if flags.isEmpty {
            return false
        }
        
        let isReachable = flags.contains(.reachable)
        let needsConnection = flags.contains(.connectionRequired)
        
        return (isReachable && !needsConnection)
    }
    
    public func getEncryptedResponseData(request: URLRequest, completionHandler:@escaping ((APIHandler) -> Void)) {
        
        EncryptedAPIClient.shared.dataRequest(request: request) { (data, response, error) in
            
            guard let cryptData = data else {
                return
            }
            
            var encryptedData = Data()
            self.getEncryptedData(data: cryptData, completionBlock: { (data) in
                
                encryptedData = data
                
            }, errorBlock: { (error) in
                
            })
            
            let handler: APIHandler = APIHandler.init(error: error, response: response, data: encryptedData)
            completionHandler(handler)
        }
    }
    
    
    //Call this methode in your class it will return the data in the encripted formate
    public func getEncryptedData(data: Data, completionBlock: (Data) -> Void, errorBlock: (Error) -> Void) {
        
        do {
            //It returns the device data in encrypted formate.
            let encrptedData = try self.encrypt(data)
            completionBlock(encrptedData)
        } catch  {
            errorBlock(Error.encryptionFailed)
        }
    }
    
    //To decrypt, pass the encrypted value with Key & inputVector values which is used for the encrytion.
    public func getDecryptedData(encrptedData:Data, completionBlock: (Data) -> Void, errorBlock: (Error) -> Void) {
        
        do {
            //It returns the decrypted data for the given encrptedData
            let decrptedData = try self.decrypt(encrptedData)
            completionBlock(decrptedData)
        } catch  {
            errorBlock(Error.decryptionFailed)
        }
    }
}

//MARK: Encrption & Decryption private methods
extension EncryptedAPIManager {
    
    //Used to encrypt the data based on the key & inputVector values
    //This will called for the Encrypt protocal function for encrypt or decrypt
    private func localEncrypt(_ data: Data) throws -> Data {
        
        let dataToEncrypt = data
        
        let bufferSize: Int = ivSize + dataToEncrypt.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        try generateRandomIV(for: &buffer)
        
        var numberBytesEncrypted: Int = 0
        
        do {
            try key.withUnsafeBytes { keyBytes in
                try dataToEncrypt.withUnsafeBytes { dataToEncryptBytes in
                    try buffer.withUnsafeMutableBytes { bufferBytes in
                        
                        guard let keyBytesBaseAddress = keyBytes.baseAddress,
                            let dataToEncryptBytesBaseAddress = dataToEncryptBytes.baseAddress,
                            let bufferBytesBaseAddress = bufferBytes.baseAddress else {
                                throw Error.encryptionFailed
                        }
                        
                        let cryptStatus: CCCryptorStatus = CCCrypt( // Stateless, one-shot encrypt operation
                            CCOperation(kCCEncrypt),                // op: CCOperation
                            CCAlgorithm(kCCAlgorithmAES),           // alg: CCAlgorithm
                            options,                                // options: CCOptions
                            keyBytesBaseAddress,                    // key: the "password"
                            key.count,                              // keyLength: the "password" size
                            bufferBytesBaseAddress,                 // iv: Initialization Vector
                            dataToEncryptBytesBaseAddress,          // dataIn: Data to encrypt bytes
                            dataToEncryptBytes.count,               // dataInLength: Data to encrypt size
                            bufferBytesBaseAddress + ivSize,        // dataOut: encrypted Data buffer
                            bufferSize,                             // dataOutAvailable: encrypted Data buffer size
                            &numberBytesEncrypted                   // dataOutMoved: the number of bytes written
                        )
                        
                        guard cryptStatus == CCCryptorStatus(kCCSuccess) else {
                            throw Error.encryptionFailed
                        }
                    }
                }
            }
            
        } catch {
            throw Error.encryptionFailed
        }
        
        let encryptedData: Data = buffer[..<(numberBytesEncrypted + ivSize)]
        return encryptedData
    }
    
    private func localDecrypt(_ data: Data) throws -> Data {
        
        let bufferSize: Int = data.count - ivSize
        var buffer = Data(count: bufferSize)
        
        var numberBytesDecrypted: Int = 0
        
        do {
            try key.withUnsafeBytes { keyBytes in
                try data.withUnsafeBytes { dataToDecryptBytes in
                    try buffer.withUnsafeMutableBytes { bufferBytes in
                        
                        guard let keyBytesBaseAddress = keyBytes.baseAddress,
                            let dataToDecryptBytesBaseAddress = dataToDecryptBytes.baseAddress,
                            let bufferBytesBaseAddress = bufferBytes.baseAddress else {
                                throw Error.encryptionFailed
                        }
                        
                        let cryptStatus: CCCryptorStatus = CCCrypt( // Stateless, one-shot encrypt operation
                            CCOperation(kCCDecrypt),                // op: CCOperation
                            CCAlgorithm(kCCAlgorithmAES128),        // alg: CCAlgorithm
                            options,                                // options: CCOptions
                            keyBytesBaseAddress,                    // key: the "password"
                            key.count,                              // keyLength: the "password" size
                            dataToDecryptBytesBaseAddress,          // iv: Initialization Vector
                            dataToDecryptBytesBaseAddress + ivSize, // dataIn: Data to decrypt bytes
                            bufferSize,                             // dataInLength: Data to decrypt size
                            bufferBytesBaseAddress,                 // dataOut: decrypted Data buffer
                            bufferSize,                             // dataOutAvailable: decrypted Data buffer size
                            &numberBytesDecrypted                   // dataOutMoved: the number of bytes written
                        )
                        
                        guard cryptStatus == CCCryptorStatus(kCCSuccess) else {
                            throw Error.decryptionFailed
                        }
                    }
                }
            }
        } catch {
            throw Error.encryptionFailed
        }
        
        let decryptedData: Data = buffer[..<numberBytesDecrypted]
        return decryptedData
    }
    
    
    private func generateRandomIV(for data: inout Data) throws {
        
        try data.withUnsafeMutableBytes { dataBytes in
            
            guard let dataBytesBaseAddress = dataBytes.baseAddress else {
                throw Error.generateRandomIVFailed
            }
            print("dataBytesBaseAddress - \(dataBytesBaseAddress)")
            
            let status: Int32 = SecRandomCopyBytes(
                kSecRandomDefault,
                kCCBlockSizeAES128,
                dataBytesBaseAddress
            )
            print("sta- \(status)")
            
            guard status == 0 else {
                throw Error.generateRandomIVFailed
            }
        }
    }
}
extension EncryptedAPIManager: Encrypter {
    
    public func encrypt(_ data: Data) throws -> Data {
        
        return try localEncrypt(data)
    }
    
    public func decrypt(_ encrypted: Data) throws -> Data {
        
        return try localDecrypt(encrypted)
    }
}
