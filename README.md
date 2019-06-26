# CryptKit

    This framework encrypts & decrypts the data
  
# Installation

    Download the application expand the product menu and drag the framwork to your application.
        
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
 
     Initially i called the API from the framwork and pass the data, error, response in model object.
     
     Later i desided to slit the API call & Cryption.
     
     So i kept the Encryption & Decryption in CryptKit and API call in test Project.
     
     Wrote some test case for Encryption & Decryption.
     
 
 # Result
     
     By passing the unencrypted data to the methode will return the Encrypted data.
     
     By passing the encrypted data to the methode will return the decrypted data.
     
    
