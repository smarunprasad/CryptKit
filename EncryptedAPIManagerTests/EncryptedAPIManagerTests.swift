//
//  EncryptedAPIManagerTests.swift
//  EncryptedAPIManagerTests
//
//  Created by Arunprasat Selvaraj on 24/06/2019.
//  Copyright © 2019 Arunprasat Selvaraj. All rights reserved.
//

import XCTest
@testable import EncryptedAPIManager

class EncryptedAPIManagerTests: XCTestCase {
    
    var encryptedAPIManager: EncryptedAPIManager!
    
    override func setUp() {
        
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        
        encryptedAPIManager = nil
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    func testForKeyCountIsEmpty() {
        
        
        do {
            encryptedAPIManager = try EncryptedAPIManager.init(key: "")
        }
        catch {
            //Throw an error for the empty key
            print(error)
            XCTAssertNotNil(error)
            guard let aesError = error as? EncryptedAPIManager.Error else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            XCTAssertEqual(aesError, .invalidKeySize, "invalidKeySize")
        }
    }
    
    func testForInvalidKey() {
        
        do {
            encryptedAPIManager = try EncryptedAPIManager.init(key: "InvalidKey")
        }
        catch {
            //Throw an error for the Invalid key
            print(error)
            guard let aesError = error as? EncryptedAPIManager.Error else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            XCTAssertEqual(aesError, .invalidKeySize, "invalidKeySize")
        }
    }
    
    func testEncryptedResponseDataMethodeForValidURL() {
        
        do {
            encryptedAPIManager = try EncryptedAPIManager.init(key: "FiugQTgPNwCWUY,VhfmM4cKXTLVFvHFe")
        }
        catch {
        }
        
        var request = URLRequest.init(url: URL.init(string: "https://api.github.com/gists/ac57abaea4faba3e3cb6bf45e733c670")!)
        request.httpMethod = "get"
        //Passing the urlRequest to encrypt API manager
        encryptedAPIManager.encryptedAPIRequest(request: request) { (_ handler) in
            
            //The handler contains the error, response, encrypted data
            var handlerData = handler
            let data = Data(bytes: &handlerData, count: MemoryLayout<APIHandler>.stride)
            
            XCTAssertNotNil(handler.data, "Data should not be nil")
            XCTAssertNil(handler.error, "error should be nil")
            XCTAssertNil(data, "data should NOT be nil")

            //Passing the data to the decrypt
            if let encrptedData = handler.data {
                    //It returns the decrypted data for the given encrptedData
                    self.encryptedAPIManager.getDecryptedData(encrptedData: encrptedData, completionBlock: { (data) in
                        //Checking for the value in decrypted data wether it contains the data or not
                        if !(data.isEmpty) {
                            do {
                                let object = try JSONSerialization.jsonObject(with: data, options: []) as? String
                                XCTAssertNotNil(object, "Dict should not be nil")
                            }
                            catch {
                            }
                        }
                    }, errorBlock: { (error) in
                    })
            }
        }
    }
    
    
    func testEncryptionforEmptyInputData() {
        
        do {
            encryptedAPIManager = try EncryptedAPIManager.init(key: "FiugQTgPNwCWUY,VhfmM4cKXTLVFvHFe")
        }
        catch {
        }
        
        encryptedAPIManager.getEncryptedData(data: Data(), completionBlock: { (data) in
           
        }) { (error) in
            //Throw an error for the empty input data
            print(error)
            XCTAssertNotNil(error)
            XCTAssertEqual(error, EncryptedAPIManager.Error.encryptionFailed, "Error should be encryptionFailed")
        }
    }
    
    func testDecryptionforEmptyEncryptedData() {
        
        do {
            encryptedAPIManager = try EncryptedAPIManager.init(key: "VhfmM4cKXTLVFvHFe")
        }
        catch {
        }
        encryptedAPIManager.getDecryptedData(encrptedData: Data(), completionBlock: { (data) in
            
        }, errorBlock: { (error) in
            //Throw an error for the empty input encrptedData
            print(error)
            XCTAssertNotNil(error)
            XCTAssertEqual(error, EncryptedAPIManager.Error.decryptionFailed, "Error should be decryptionFailed")
        })
    }
    
    func testEncryptionandDecryptionforInValidValue() {

        do {
            encryptedAPIManager = try EncryptedAPIManager.init(key: "FiugQTgPNwCWUY,VhfmM4cKXTLVFvHFe")
        }
        catch {
        }
        encryptedAPIManager.getEncryptedData(data: "Encrypted data".data(using: .utf8)!, completionBlock: { (data) in
           //Passing the different key for testing.
            do {
                encryptedAPIManager = try EncryptedAPIManager.init(key: "VhfmM4cKXTLVFvHFe")
            }
            catch {
            }
            //Passing the data to decrypt
            encryptedAPIManager.getDecryptedData(encrptedData: data, completionBlock: { (data) in
               
            }, errorBlock: { (error) in
                //Throw an error for the different key decryptionFailed
                print(error)
                XCTAssertNotNil(error)
                XCTAssertEqual(error, EncryptedAPIManager.Error.decryptionFailed, "decryptionFailed maybe due to different key")
            })
        }) { (error) in
            
            print(error)
        }
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }
    
}
