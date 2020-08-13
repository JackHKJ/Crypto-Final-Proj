import socket
from KEYgen import ECCsrv
from Algorithms import *
from ECCryp import *
from ElGamal import *
from MACer import *
from KEYgen import *


def decryptorServer(method, ciphertext, macKey, decryptKey):
    #decrypt
    textWithMAC = ""
    if method == "ELG":
        textWithMAC = Decrypt32bit(decryptKey, ciphertext)
    elif method == "DES":
        textWithMAC = CBC_DES_decrypt(ciphertext, decryptKey)
    elif method == "ECC":
        textWithMAC = koblitz_de_str(ciphertext, decryptKey)
    else:
        print("Error, invalid en/decryption method" )
        return "Error, invalid en/decryption method" 
    #print(textWithMAC)    
    #verify mac
    #"$REJECT" will be returned on error
    # print(textWithMAC)
    plain = verifyMacServer(textWithMAC, macKey)
    return plain
    
    
def encryptorServer(method, plaintext, macKey, encryptkey):
    textwithMAC = addMacServer(plaintext, macKey)
    ciphertext = ""
    if method == "ELG":
        ciphertext = Encrypt32bit(encryptkey, textwithMAC)
    elif method == "DES":
        ciphertext = CBC_DES_encrypt(textwithMAC, encryptkey)
    elif method == "ECC":
        ciphertext = koblitz_en_str(textwithMAC, encryptkey)
    else:
        print("Error, invalid en/decryption method")
        return "Error, invalid en/decryption method" 
    return ciphertext

def decryptorClient(method, ciphertext, macKey, decryptKey):
    #decrypt
    textWithMAC = ""
    if method == "ELG":
        textWithMAC = Decrypt32bit(decryptKey, ciphertext)
    elif method == "DES":
        textWithMAC = CBC_DES_decrypt(ciphertext, decryptKey)
    elif method == "ECC":
        textWithMAC = koblitz_de_str(ciphertext, decryptKey)
    else:
        print("Error, invalid en/decryption method" )
        return "Error, invalid en/decryption method" 
    #print(textWithMAC)    
    #verify mac
    #"$REJECT" will be returned on error
    # print(textWithMAC)
    plain = verifyMacClient(textWithMAC, macKey)
    return plain
    
    
def encryptorClient(method, plaintext, macKey, encryptkey):
    textwithMAC = addMacClient(plaintext, macKey)
    ciphertext = ""
    if method == "ELG":
        ciphertext = Encrypt32bit(encryptkey, textwithMAC)
    elif method == "DES":
        ciphertext = CBC_DES_encrypt(textwithMAC, encryptkey)
    elif method == "ECC":
        ciphertext = koblitz_en_str(textwithMAC, encryptkey)
    else:
        print("Error, invalid en/decryption method")
        return "Error, invalid en/decryption method" 
    return ciphertext



if __name__ == "__main__":
    # ELG
    pub, pri = KeyGen()
    macKey = "thisIsAMacKey"
    plain = "ABCD1234"
    cipherText = encryptorServer("ELG",plain,macKey,pub)
    print(cipherText)
    plainText = decryptorClient("ELG",cipherText,macKey,pri)
    print(plainText)
    
    # DES
    pub = pri = keygen()
    print("haha", pri)
    macKey = "thisIsAMacKey"
    plain = "ABCD1234"
    cipherText = encryptorClient("DES",plain,macKey,pub)
    print(cipherText)
    plainText = decryptorServer("DES",cipherText,macKey,pri)
    print(plainText)    
    
    
    ## ECC
    pri, pub = make_keypair()
    macKey = "thisIsAMacKey"
    plain = "123"
    cipherText = encryptorServer("ECC",plain,macKey,pub)
    print(cipherText)
    plainText = decryptorClient("ECC",cipherText,macKey,pri)
    print(plainText)
    
