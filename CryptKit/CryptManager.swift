//
//  CryptManager.swift
//  CryptManager
//
//  Created by Arunprasat Selvaraj on 25/06/2019.
//  Copyright © 2019 Arunprasat Selvaraj. All rights reserved.
//

import Foundation
import CommonCrypto
import Security

public protocol Crypter {
    
    func encrypt(_ data: Data) throws -> Data
    func decrypt(_ encrypted: Data) throws -> Data
}

class CryptManager {
    
    //Variables
    var key: Data
    let ivSize: Int  = kCCBlockSizeAES128
    private let options: CCOptions = CCOptions(kCCOptionPKCS7Padding)
  
    //Init
    public init(key: String) throws {
        //Checking for the key is empty or not
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
    
    //MARK: Encrption & Decryption private methods
    
    //Used to encrypt the data
    func localEncrypt(_ data: Data) throws -> Data {
        
        let dataToEncrypt = data

        //Creating the Int value from the data & kCCBlockSizeAES128
        let bufferSize: Int = ivSize + dataToEncrypt.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        
        //Generating the random value basedd on the buffer
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
                            keyBytesBaseAddress,                    // key: the "key"
                            key.count,                              // keyLength: the "key" size
                            bufferBytesBaseAddress,                 // iv: Init Vector
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
    
    //Used to decrypt the data based
    func localDecrypt(_ data: Data) throws -> Data {
        
        //Creating the Int value from the data & ivSize
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
                            keyBytesBaseAddress,                    // key: the "key"
                            key.count,                              // keyLength: the "key" size
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
    
    //Generating the random input vector from the data
    private func generateRandomIV(for data: inout Data) throws {
        
        try data.withUnsafeMutableBytes { dataBytes in
            
            guard let dataBytesBaseAddress = dataBytes.baseAddress else {
                throw Error.generateRandomIVFailed
            }
            
            //For valid dataBytesBaseAddress it returns 0
            let status: Int32 = SecRandomCopyBytes(
                kSecRandomDefault,
                kCCBlockSizeAES128,
                dataBytesBaseAddress
            )
            
            guard status == 0 else {
                throw Error.generateRandomIVFailed
            }
        }
    }
    
    //Call this methode in your class it will return the data in the encripted formate
    public func getEncryptedData(data: Data, completionBlock: (Data) -> Void, errorBlock: (Error) -> Void) {
        
        guard !(data.isEmpty) else {
            errorBlock(Error.encryptionFailed)
            return
        }
        do {
            //It returns the device data in encrypted formate.
            do {
                //To pass the data to encryption.
                let encrptedData = try self.encrypt(data)
                completionBlock(encrptedData)
            }
            
        } catch  {
            
            errorBlock(Error.encryptionFailed)
        }
    }
    
    //To decrypt, pass the encrypted value with Key & inputVector values which is used for the encrytion.
    public func getDecryptedData(encrptedData: Data, completionBlock: (Data) -> Void, errorBlock: (Error) -> Void) {
        
        guard !(encrptedData.isEmpty) else {
            errorBlock(Error.decryptionFailed)
            return
        }
        
        do {
            //It returns the decrypted data for the given encrptedData
            do {
                //To pass the data to decryption.
                let decrptedData = try self.decrypt(encrptedData)
                completionBlock(decrptedData)
            }

        } catch  {
            
            errorBlock(Error.decryptionFailed)
        }
    }
}

extension CryptManager: Crypter {
    
    public func encrypt(_ data: Data) throws -> Data {
        
        return try self.localEncrypt(data)
    }
    
    public func decrypt(_ encrypted: Data) throws -> Data {
        
        return try self.localDecrypt(encrypted)
    }
}
