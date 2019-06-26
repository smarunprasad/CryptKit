# CryptKit

    This framework is used to encrypt & decrypt the data
  
# Installation

    Download the application expand the product menu and drag the framwork to your application.
    
    Add the framwork to the Embedded framwork tab in Generaal tab.
    
    Import the CryptKit to your class and use it.
  
  
# Key

    FiugQTgPNwCWUY,VhfmM4cKXTLVFvHFe
    
    
 # Usage
    
    var cryptManager: CryptManager!
    do {
      cryptManager = try CryptManager.init(key: "FiugQTgPNwCWUY,VhfmM4cKXTLVFvHFe")
    } catch {
        
    }
        
   # Encrypt
        
     cryptManager.getEncryptedData(data: dataToEncrypt, completionBlock: { (data) in
            
     }) { (error) in
            
     }
          
   # Decrypt
           
      cryptManager.getDecryptedData(encrptedData: data, completionBlock: { (data) in
           
      }) { (error) in
            
      }
           
# Also use the Crypter Protocol to encrypt & decrypt the data
     
    public func encrypt(_ data: Data) throws -> Data

    public func decrypt(_ encrypted: Data) throws -> Data
  

    
 # Approach
 
     Initially i tried to call the API inside the library and pass the data, error, response in model object.
     
     Then i feel to slit the API call & Cryption.
     
     So i keep the Encryption & Decryption in CryptKit and the API call the test Project
     
     Then write the test case for the Encryption & Decryption in all the cases.
     
 
 # Result
     
     This Kit returns the Encrypted data if you send the data to it.
     
     Returns the decrypted data if you send the Encrypted data. 
    
