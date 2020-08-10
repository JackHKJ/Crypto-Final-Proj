## this is an implementation of automatically adding / verify and stripting MAC from msg
## usage:
## msgWithMac =addMAC(msg, key)
## msg = verifyMAC( msgWithMac, key)


import hashlib
import hmac
import base64

## this HMAC-SHA1 function make_digest(message, key) is imported from
## https://gist.github.com/heskyji/5167567b64cb92a910a3
## Credit to author: heskyji
def make_digest(message, key):
    
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


if __name__ == "__main__":
    msg1 = "A.AAA"
    msg2 = "AA.AA"
    key = "private-key"
    msgWithMac = addMAC(msg1,key)
    print(msgWithMac)
    print(verifyMAC(msgWithMac,key))
    assert((make_digest(msg1,key) != make_digest(msg2,key)))    