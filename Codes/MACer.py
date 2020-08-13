## this is an implementation of automatically adding / verify and stripting MAC from msg
## usage:
## msgWithMac =addMAC(msg, key)
## msg = verifyMAC( msgWithMac, key)

import hashlib
import hmac
import base64
import random

SERVERNONCE = set()
nonceStorage = open("SERVERNONCE.txt",mode="r")
for line in nonceStorage:
    #print(line)
    if len(line) == 0:
        continue
    SERVERNONCE.add(line.rstrip("\n"))
nonceStorage.close()

CLIENTNONCE = set()
nonceStorage = open("CLIENTNONCE.txt",mode="r")
for line in nonceStorage:
    #print(line)
    if len(line) == 0:
        continue
    CLIENTNONCE.add(line.rstrip("\n"))
nonceStorage.close()

## this HMAC-SHA1 function make_digest(message, key) is imported from
## https://gist.github.com/heskyji/5167567b64cb92a910a3
## Credit to author: heskyji
def make_digest(message, key):
    key = str(key)
    key = bytes(key, 'UTF-8')
    message = bytes(message, 'UTF-8')    
    digester = hmac.new(key, message, hashlib.sha1)
    #signature1 = digester.hexdigest()
    signature1 = digester.digest()
    #print(signature1)    
    #signature2 = base64.urlsafe_b64encode(bytes(signature1, 'UTF-8'))
    signature2 = base64.urlsafe_b64encode(signature1)    
    #print(signature2)    
    return str(signature2, 'UTF-8')
  

#result = make_digest('message', 'private-key')
#print(result)
#print(len(result))

## add the MAC to the end of the message
def addMAC(msg, key = "default-key"):
    MAC = make_digest(msg,key)
    return msg + MAC

## verify the MAC
## if verified, strip the MAC and return the real message
## if false, return "$REJECT"
def verifyMAC(msg, key):
    msg = str(msg)
    key = str(key)
    if len(msg) <= 28 or len(key) == 0:
        return "$REJECT"
    MAC = msg[-28:]
    msg = msg[:-28]
    if MAC == make_digest(msg, key):
        return msg
    return "$REJECT"

def addMacServer(msg, key = "default-key"):
    msg = addNonceServer(str(msg))
    return addMAC(msg, key)

def verifyMacServer(msg, key):
    msg = str(msg)
    msg = verifyMAC(msg, key)
    msg = verifyNonceServer(msg)
    return msg

def addMacClient(msg, key = "default-key"):
    msg = addNonceClient(str(msg))
    return addMAC(msg, key)

def verifyMacClient(msg, key):
    msg = str(msg)
    msg = verifyMAC(msg, key)
    msg = verifyNonceClient(msg)
    return msg





def addNonceServer(msg):
    msg = str(msg)
    thisNonce = 0
    while True:
        thisNonce = random.randint(10**31, 10**32)
        thisNonce = str(thisNonce)
        if not thisNonce in SERVERNONCE:
            SERVERNONCE.add(thisNonce)
            nonceStorage = open("SERVERNONCE.txt",mode="a")
            nonceStorage.write("\n"+str(thisNonce))
            nonceStorage.close()
            #print(SERVERNONCE)
            break
    msg += str(thisNonce)
    return msg


def addNonceClient(msg):
    msg = str(msg)
    thisNonce = 0
    while True:
        thisNonce = random.randint(10**31, 10**32)
        thisNonce = str(thisNonce)
        if not thisNonce in CLIENTNONCE:
            CLIENTNONCE.add(thisNonce)
            nonceStorage = open("CLIENTNONCE.txt",mode="a")
            nonceStorage.write("\n"+str(thisNonce))
            nonceStorage.close()
            #print(CLIENTNONCE)
            break
    msg += str(thisNonce)
    return msg



def verifyNonceClient(msg):
    if len(msg) <= 16:
        return "$REJECT"
    nonce = msg[-32:]
    if nonce in CLIENTNONCE:
        return "$REJECT"
    CLIENTNONCE.add(nonce)
    nonceStorage = open("CLIENTNONCE.txt",mode="a")
    nonceStorage.write("\n"+str(nonce))
    nonceStorage.close()
    return msg[:-32]

def verifyNonceServer(msg):
    if len(msg) <= 16:
        return "$REJECT"
    nonce = msg[-32:]
    if nonce in SERVERNONCE:
        return "$REJECT"
    SERVERNONCE.add(nonce)
    nonceStorage = open("SERVERNONCE.txt",mode="a")
    nonceStorage.write("\n"+str(nonce))
    nonceStorage.close()
    return msg[:-32]




if __name__ == "__main__":
    msg1 = "A.AAA"
    msg2 = "AA.AA"
    key = "private-key"
    msgWithMac = addMacClient(msg1,key)
    print(msgWithMac)
    print(verifyMacServer(msgWithMac,key))
    assert((make_digest(msg1,key) != make_digest(msg2,key)))    
    
    #onePNonce = addNonceClient("MESSAGE")
    #print(onePNonce)
    #plain = verifyNonceServer(onePNonce)
    #print(plain)