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
        
        do {
            encryptedAPIManager = try EncryptedAPIManager.init(key: "8C182623CD047A0D6593691B2179B98440A91AF01E4BB2BD90D49CC9E9D171E7".data(using: .utf8) ?? Data(), iv: "8DB023E39C39B95EBC0155DA9F14C37D".data(using: .utf8) ?? Data())
        }
        catch {
            print(error)
        }
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        
        encryptedAPIManager = nil
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    func testEncryptedResponseDataMethodeForValidURL() {
        
        var request = URLRequest.init(url: URL.init(string: "https://api.github.com/gists/ac57abaea4faba3e3cb6bf45e733c670")!)
        request.httpMethod = "get"
        request.httpBody = "iOS".data(using: .utf8)
        encryptedAPIManager.getEncryptedResponseData(request: request) { (_ handler) in
            
            XCTAssertNotNil(handler.data, "Data should not be nil")
            XCTAssertNil(handler.error, "error should be nil")
            
            if let encrptedData = handler.data {
                do {
                    //It returns the decrypted data for the given encrptedData
                    let decrptedData = try self.encryptedAPIManager.decrypt(encrptedData)
                    do {
                        let object = try JSONSerialization.jsonObject(with: decrptedData, options: []) as? String
                        
                        XCTAssertNotNil(object, "Dict should not be nil")
                    }
                    catch {
                        
                        XCTAssertNotNil(error, "error should not be nil")
                    }
                } catch  {
                    
                }
            }
        }
    }
    
    func testEncryptionandDecryptionforValidValue() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        
        encryptedAPIManager.getEncryptedData(data: Data(), completionBlock: { (data) in
            
            encryptedAPIManager.getDecryptedData(encrptedData: data, completionBlock: { (data) in
                
                do {
                    let dict = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
                    
                    XCTAssertNotNil(dict, "The value should not be nil")
                }
                catch {
                    print(error)
                }
            }, errorBlock: { (error) in
                print(error)
            })
        }) { (error) in
            
            print(error)
        }
    }
    
    
    
    func testEncryptionandDecryptionforInValidKey() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        
        do {
            encryptedAPIManager = try EncryptedAPIManager.init(key: "dafqwefgrth".data(using: .utf8) ?? Data(), iv: "8DB023E39C39B95EBC0155DA9F14C37D".data(using: .utf8) ?? Data())
        }
        catch {
            XCTAssertEqual(error.localizedDescription, "badKeyLength", "")
            print(error)
        }
        
        encryptedAPIManager.getEncryptedData(data: Data(), completionBlock: { (data) in
            
        }) { (error) in
            
            XCTAssertNotNil(error, "error should not be nil")
        }
    }
    
    func testDecryptionforInValidInput() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        
        do {
            encryptedAPIManager = try EncryptedAPIManager.init(key: "8C182623CD047A0D6593691B2179B98440A91AF01E4BB2BD90D49CC9E9D171E7".data(using: .utf8) ?? Data(), iv: "8DB023E39C39B95EBC0155DA9F14C37D".data(using: .utf8) ?? Data())
        }
        catch {
            print(error)
        }
        
        encryptedAPIManager.getDecryptedData(encrptedData: Data(), completionBlock: { (data) in
            
        }, errorBlock: { (error) in
            XCTAssertNotNil(error, "error should not be nil")
        })
    }
    
    func testDecriptionforInValidValue() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        
        do {
            encryptedAPIManager = try EncryptedAPIManager.init(key: "8C182623CD047A4D6593691B2179B98440A91AF01E4BB2BD90D49CC9E9D171E7".data(using: .utf8) ?? Data(), iv: "14C37D8DB023E39C39B95EBC0155DA9F".data(using: .utf8) ?? Data())
        }
        catch {
            print(error)
        }
        
        encryptedAPIManager.getEncryptedData(data: Data(), completionBlock: { (data) in
            
            encryptedAPIManager.getDecryptedData(encrptedData: data, completionBlock: { (data) in
                
                do {
                    let _ = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
                    
                }
                catch {
                    
                    XCTAssertNotNil(error, "error should not be nil")
                }
            }, errorBlock: { (error) in
                print(error)
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
