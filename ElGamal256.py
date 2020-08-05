import math
import random
from StringBinaryConverter import *
##USAGE:
##  to_binary(string)
##  to_string(binary)
##  Encoder32(string)
##  Decode32(binary)


## from the Jacobian method on CrypoSec_L7.1.pdf page 23
##/x\
##|-|
##\n/
def Jacobian(x,n):
    if (x == 1):
        return 1
    if x == 0:
        if n == 1:
            return 1
        return 0
    if x == -1:
        if n % 2 == 0:
            return 1
        return -1
    if x == 2:
        if n % 8 in [1,7]:
            return 1
        if n % 8 in [3,5]:
            return -1  
    if (x >= n):
        return Jacobian(x%n, n)
    if x % 2 == 0:
        return Jacobian(2, n)*Jacobian(x//2, n)
    if x % 4 == 3 and n % 4 == 3:
        return -1 * Jacobian( n, x)
    else:
        return Jacobian(n, x )        
        #if ((n**2 -1)/8 % 2) == 0:
            #return Jacobian(x/2,n)
        #return -1 * Jacobian(x/2,n)    
    if (((x-1) * (n-1) / 4 ) % 2) == 0:
        return Jacobian(n % x, x)
    return -1 * Jacobian (n % x, x)
    
def HasGCD(n1, n2):
    while n2 != 0:
        swap = n1 % n2
        n1 = n2
        n2 = swap
    if n1 > 0:
        return False;
    return True;


def moduloExponent( base, power, modulo):
    return pow(base,power,modulo)

## use solovay-strassen to test whether the number is a prime or not
def primeTest(number):
    for i in range (32):
        rand = random.randint(1,number-1)
        if HasGCD(rand,number):
            return False;
        ## CrypoSec_L7.1.pdf, page 25
        if not  Jacobian(rand,number) % number == moduloExponent(rand, (number-1)//2, number):
            return False;
    return True



def generatePrime():
    while(True):
        ## generation of a 32bit number
        rand = random.randint(2 ** 254, 2** 255)
        if rand % 2 == 0:
            continue;
        if not primeTest(rand):
            continue;
        if not primeTest(rand * 2 + 1):
            continue;
        return rand * 2 + 1
        
        
#imported from internet, credit to: 
#http://modular.math.washington.edu/edu/2007/spring/ent/ent-html/node31.html
def find_primitive_root( p ):
    if p == 2:
        return 1
    p1 = 2
    p2 = (p-1) // p1
    while( 1 ):
        g = random.randint( 2, p-1 )
        if not (moduloExponent( g, (p-1)//p1, p ) == 1):
            if not moduloExponent( g, (p-1)//p2, p ) == 1:
                return g
        


## generate 32 bit key pair
## on return: [0]: public key [1]: private key
def KeyGen():    
    p = generatePrime()
    g = moduloExponent(find_primitive_root(p), 2 , p)
    x = random.randint(1, (p-1) // 2)
    h = moduloExponent(g,x,p)
    #[public,private]
    return [[p,g,h],[p,g,x]]
    

## param: publicKeySet: the public key set in sequence p,g,h
def Encrypt64bit(publicKeySet,msg):
    ## seperate the keyset
    p = publicKeySet[0]
    g = publicKeySet[1]
    h = publicKeySet[2]
    
    message = Encoder64(msg)
    
    ## for debugging
    if __name__ == "__main__":        
        print(msg+":")
        print(message)
        
     
    encrypt_pair = []
    for i in range(0,len(message),64):
        thisNum = int(message[i:i+64])
        y = random.randint(0, p )
        c = moduloExponent( g, y, p)
        d = (thisNum*moduloExponent( h, y, p)) % p
        encrypt_pair.append( [c, d] )
    encryptedStr = ""
    for thisPair in encrypt_pair:
        encryptedStr += str(thisPair[0]) + ' ' + str(thisPair[1]) + ' '
    return encryptedStr   
    

## param: privateKeySet: the private key set in sequence p,g,x
def Decrypt64bit(privateKeySet ,msg):
    
    p = privateKeySet[0]
    g = privateKeySet[1]
    x = privateKeySet[2]
    
    ret = ""
    msgList = msg.split()
    for i in range(0, len(msgList), 2):
        c = int(msgList[i])
        d = int(msgList[i+1])
        s = moduloExponent( c, x, p)
        text = (d*moduloExponent( s,p-2, p)) % p
        text = str(text)
        while(len(text)< 64):
            text = "0"+text
        ret += text        
    retDec = Decoder64(ret)
    return retDec
    
    
    
if __name__ == "__main__":
    keySet = KeyGen()
    ## p,g,h
    publicKey = keySet[0]
    ## p,g,x
    privateKey = keySet[1]
        
    
    plainText = "AAAA"   
    cipherText = (Encrypt64bit(publicKey,plainText));
    print(cipherText)
    recoveredText = (Decrypt64bit(privateKey,cipherText));
    print(recoveredText)    
