import socket
from KEYgen import ECCsrv
from Algorithms import *
from ECCryp import *
from ElGamal import *
from MACer import *

def decryptor(method, ciphertext, macKey, decryptKey):
    #decrypt
    textWithMAC = ""
    if method == "ELG":
        textWithMAC = Decrypt32bit(decryptKey, ciphertext)
    elif method == "DES":
        textWithMAC = CBC_DES_decrypt(ciphertext, decryptKey)
    elif method == "ECC":
        textWithMAC == koblitz_de(ciphertext, decryptKey)
    else:
        print("Error, invalid en/decryption method" )
        return "Error, invalid en/decryption method" 
    print(textWithMAC)    
    #verify mac
    #"$REJECT" will be returned on error
    plain = verifyMAC(textWithMAC, macKey)
    return plain
    
    
def encryptor(method, plaintext, macKey, encryptkey):
    textwithMAC = addMAC(plaintext, macKey)
    if method == "ELG":
        ciphertext = Encrypt32bit(encryptkey, textwithMAC)
    elif method == "DES":
        ciphertext = CBC_DES_encrypt(textwithMAC, encryptkey)
    elif method == "ECC":
        ciphertext == koblitz_en(textwithMAC, encryptkey)
    else:
        print("Error, invalid en/decryption method")
        return "Error, invalid en/decryption method" 
    return ciphertext

if __name__ == "__main__":
    
    ## ELG
    pub, pri = KeyGen()
    macKey = "thisIsAMacKey"
    plain = "ABCD1234"
    cipherText = encryptor("ELG",plain,macKey,pub)
    print(cipherText)
    plainText = decryptor("ELG",cipherText,macKey,pri)
    print(plainText)
    
    ## DES
    pub = pri = keygen()
    macKey = "thisIsAMacKey"
    plain = "ABCD1234"
    cipherText = encryptor("DES",plain,macKey,pub)
    print(cipherText)
    plainText = decryptor("DES",cipherText,macKey,pri)
    print(plainText)    
    
    