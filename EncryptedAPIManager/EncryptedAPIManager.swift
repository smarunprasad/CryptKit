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

public protocol Encrypter {
    
    func encrypt(_ data: Data) throws -> Data
    func decrypt(_ encrypted: Data) throws -> Data
}

public class EncryptedAPIManager {
    
    //Variables
    private var key: Data
    private var inputVector: Data
    
    //Init
    public init(key: Data, iv: Data) throws {
        guard !(key.isEmpty) else {
            throw EncryptionError.badKeyLength
        }
        guard !(iv.isEmpty) else {
            throw EncryptionError.badInputVectorLength(iv: iv)
        }
        self.key = key
        self.inputVector = iv
    }
    
    public enum EncryptionError: Swift.Error {
        case keyGeneration(status: Int)
        case encryptFailed
        case badKeyLength
        case badInputVectorLength(iv: Data)
    }

//Call this methode in your class it will return the device in the encripted formate
open func getEncryptedData(data: Data, completionBlock: (Data) -> Void, errorBlock: (Error) -> Void) {
    
    do {
        //It returns the device data in encrypted formate.
        let encrptedData = try self.encrypt(data)
        completionBlock(encrptedData)
    } catch  {
        errorBlock(EncryptionError.encryptFailed)
    }
}

//To decrypt, pass the encrypted value with Key & inputVector values which is used for the encrytion.
open func getDecryptedData(encrptedData:Data, completionBlock: (Data) -> Void, errorBlock: (Error) -> Void) {
    
    do {
        //It returns the decrypted data for the given encrptedData
        let decrptedData = try self.decrypt(encrptedData)
        completionBlock(decrptedData)
    } catch  {
        errorBlock(EncryptionError.encryptFailed)
    }
}

// Used to encrypt or decrypt the data based on the key & inputVector values
// This will called for the Encrypt protocal function for encrypt or decrypt
private func crypt(input: Data, operation: CCOperation) throws -> Data {
    
    let outputLength = input.count + kCCBlockSizeAES128
    var outputBuffer = Array<UInt8>(repeating: 0,
                                    count: outputLength)
    var numBytesEncrypted = 0
    
    let status = CCCrypt(CCOperation(kCCEncrypt), // operation
        CCAlgorithm(kCCAlgorithmAES),   // algorithm
        CCOptions(kCCOptionPKCS7Padding), // options
        Array(key),  // key
        kCCKeySizeAES256, // keylength
        Array(inputVector), // iv
        Array(input), // dataIn
        input.count, // dataInLength
        &outputBuffer, // dataOut
        outputLength, // dataOutLength
        &numBytesEncrypted) // dataOutMoved
    
    guard status == kCCSuccess else {
        throw EncryptionError.encryptFailed
    }
    
    let outputBytes = outputBuffer.prefix(numBytesEncrypted)
    return Data(outputBytes)
}
}


extension EncryptedAPIManager: Encrypter {
    
    public func encrypt(_ data: Data) throws -> Data {
        
        return try crypt(input: data, operation: CCOperation(kCCEncrypt))
    }
    
    public func decrypt(_ encrypted: Data) throws -> Data {
        
        return try crypt(input: encrypted, operation: CCOperation(kCCDecrypt))
    }
}
