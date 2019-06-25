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
    var key: Data
    var encryptManager: EncryptManager!
    
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
    
    func encriptionManagerInit() {
        
        do {
            //To pass the key to encryptManager class for encryption.
            let manager = try EncryptManager.init(key: self.key)
            self.encryptManager = manager
        }
        catch {
            
        }
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
    
    // This methode returns the encrypted data for the urlrequest send to it
    public func encryptedAPIRequest(request: URLRequest, completionHandler:@escaping ((APIHandler) -> Void)) {
        
        //API call using urlsession
        EncryptedAPIClient.shared.dataRequest(request: request) { (data, response, error) in
            
            guard let cryptData = data else {
                return
            }
            var encryptedData = Data()
            //Converting the data from the response to encrytped data.
            self.getEncryptedData(data: cryptData, completionBlock: { (data) in
                encryptedData = data
            }, errorBlock: { (error) in
            })
            
            //APIHandler is used to pass the error, response & encrypted data to completionHandler
            let handler: APIHandler = APIHandler.init(error: error, response: response, data: encryptedData)
            completionHandler(handler)
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
            let encrptedData = try self.encrypt(data)
            completionBlock(encrptedData)
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
            let decrptedData = try self.decrypt(encrptedData)
            completionBlock(decrptedData)
        } catch  {
            errorBlock(Error.decryptionFailed)
        }
    }
}

extension EncryptedAPIManager: Encrypter {
    
    public func encrypt(_ data: Data) throws -> Data {
        
        return try self.encryptManager.localEncrypt(data)
    }
    
    public func decrypt(_ encrypted: Data) throws -> Data {
        
        return try self.encryptManager.localDecrypt(encrypted)
    }
}
