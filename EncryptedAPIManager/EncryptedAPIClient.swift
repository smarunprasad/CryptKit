//
//  EncryptedAPIClient.swift
//  EncryptedAPIManager
//
//  Created by Arunprasat Selvaraj on 25/06/2019.
//  Copyright © 2019 Arunprasat Selvaraj. All rights reserved.
//

import Foundation
import SystemConfiguration

final class EncryptedAPIClient {
    
    static let shared = EncryptedAPIClient()
    private let session = URLSession.shared
    
    func dataRequest(request: URLRequest, completionHandler:@escaping ((Data?, URLResponse?, Error?) -> Void)) {
        
        // API call using dataTask
        let dataTask = session.dataTask(with: request as URLRequest) { (data, response, error) in
            //Passing the (data, response, error) to completionHandler
            completionHandler(data, response, error)
        }
        dataTask.resume()
    }
}
