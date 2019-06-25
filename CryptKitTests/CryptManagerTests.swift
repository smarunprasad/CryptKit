//
//  CryptManagerTests.swift
//  CryptManagerTests
//
//  Created by Arunprasat Selvaraj on 24/06/2019.
//  Copyright © 2019 Arunprasat Selvaraj. All rights reserved.
//

import XCTest
@testable import CryptKit

class CryptManagerTests: XCTestCase {
    
    var cryptManager: CryptManager!
    
    override func setUp() {
        
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        
        cryptManager = nil
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    func testForKeyCountIsEmpty() {
        
        do {
            cryptManager = try CryptManager.init(key: "")
        }
        catch {
            //Throw an error for the empty key
            print(error)
            XCTAssertNotNil(error)
            guard let aesError = error as? CryptManager.Error else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            XCTAssertEqual(aesError, .invalidKeySize, "invalidKeySize")
        }
    }
    
    func testForInvalidKey() {
        
        do {
            cryptManager = try CryptManager.init(key: "InvalidKey")
        }
        catch {
            //Throw an error for the Invalid key
            print(error)
            guard let cryptError = error as? CryptManager.Error else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            XCTAssertEqual(cryptError, .invalidKeySize, "invalidKeySize")
        }
    }
    
    func testEncryptedResponseDataMethodeForValidURL() {
        
        do {
            cryptManager = try CryptManager.init(key: "FiugQTgPNwCWUY,VhfmM4cKXTLVFvHFe")
        }
        catch {
        }
        
        cryptManager.getEncryptedData(data: "please encrypt".data(using: .utf8)!, completionBlock: { (data) in
            
            cryptManager.getDecryptedData(encrptedData: data, completionBlock: { (data) in
                
            }) { (error) in
                
            }
        }) { (error) in
            
        }
    }
    
    func testEncryptionforEmptyInputData() {
        
        do {
            cryptManager = try CryptManager.init(key: "FiugQTgPNwCWUY,VhfmM4cKXTLVFvHFe")
        }
        catch {
        }
        
        cryptManager.getEncryptedData(data: Data(), completionBlock: { (data) in
           
        }) { (error) in
            //Throw an error for the empty input data
            print(error)
            XCTAssertNotNil(error)
            XCTAssertEqual(error, CryptManager.Error.encryptionFailed, "Error should be encryptionFailed")
        }
    }
    
    func testDecryptionforEmptyEncryptedData() {
        
        do {
            cryptManager = try CryptManager.init(key: "VhfmM4cKXTLVFvHFe")
        }
        catch {
        }
        cryptManager.getDecryptedData(encrptedData: Data(), completionBlock: { (data) in
            
        }, errorBlock: { (error) in
            //Throw an error for the empty input encrptedData
            print(error)
            XCTAssertNotNil(error)
            XCTAssertEqual(error, CryptManager.Error.decryptionFailed, "Error should be decryptionFailed")
        })
    }
    
    func testEncryptionandDecryptionforInValidValue() {

        do {
            cryptManager = try CryptManager.init(key: "FiugQTgPNwCWUY,VhfmM4cKXTLVFvHFe")
        }
        catch {
        }
        cryptManager.getEncryptedData(data: "Encrypted data".data(using: .utf8)!, completionBlock: { (data) in
           //Passing the different key for testing.
            do {
                cryptManager = try CryptManager.init(key: "VhfmM4cKXTLVFvHFe")
            }
            catch {
            }
            //Passing the data to decrypt
            cryptManager.getDecryptedData(encrptedData: data, completionBlock: { (data) in
               
            }, errorBlock: { (error) in
                //Throw an error for the different key decryptionFailed
                print(error)
                XCTAssertNotNil(error)
                XCTAssertEqual(error, CryptManager.Error.decryptionFailed, "decryptionFailed maybe due to different key")
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
