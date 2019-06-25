//
//  EncryptManager.swift
//  EncryptedAPIManager
//
//  Created by Arunprasat Selvaraj on 25/06/2019.
//  Copyright © 2019 Arunprasat Selvaraj. All rights reserved.
//

import Foundation
import CommonCrypto
import Security

class EncryptManager {
    
    //Variables
    var key: Data
    let ivSize: Int  = kCCBlockSizeAES128
    private let options: CCOptions = CCOptions(kCCOptionPKCS7Padding)

    //Init
    public init(key: Data) throws {
       
        self.key = key
    }
    
    //MARK: Encrption & Decryption private methods
    
    //Used to encrypt the data
    func localEncrypt(_ data: Data) throws -> Data {
        
        let dataToEncrypt = data
//        else {
//
//            throw EncryptedAPIManager.Error.encryptionFailed
//           // return Data()
//        }
        
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
                                throw EncryptedAPIManager.Error.encryptionFailed
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
                            throw EncryptedAPIManager.Error.encryptionFailed
                        }
                    }
                }
            }
            
        } catch {
            throw EncryptedAPIManager.Error.encryptionFailed
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
                                throw EncryptedAPIManager.Error.encryptionFailed
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
                            throw EncryptedAPIManager.Error.decryptionFailed
                        }
                    }
                }
            }
        } catch {
            throw EncryptedAPIManager.Error.encryptionFailed
        }
        
        let decryptedData: Data = buffer[..<numberBytesDecrypted]
        return decryptedData
    }
    
    //Generating the random input vector from the data
    private func generateRandomIV(for data: inout Data) throws {
        
        try data.withUnsafeMutableBytes { dataBytes in
            
            guard let dataBytesBaseAddress = dataBytes.baseAddress else {
                throw EncryptedAPIManager.Error.generateRandomIVFailed
            }
            
            //For valid dataBytesBaseAddress it returns 0
            let status: Int32 = SecRandomCopyBytes(
                kSecRandomDefault,
                kCCBlockSizeAES128,
                dataBytesBaseAddress
            )
            
            guard status == 0 else {
                throw EncryptedAPIManager.Error.generateRandomIVFailed
            }
        }
    }
}
