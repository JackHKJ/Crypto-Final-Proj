import socket
from KEYgen import *
from Algorithms import *
from ECCryp import *
from IntegratedEnDecryptor import *

#en_method = "ELG"
en_method = input("Enter the encryption method (ELG/ECC/DES) you want: ")
if en_method != "ELG" and en_method != "ECC" and en_method != "DES":
    en_method = "ELG"
#KEYS GOES HERE, TESTING ONLY!!!
pri, pub = 17266110910292182863031101798374952031947451314643790344773650325784057863506, (63418887483913902302210242333028958573736406591311866468970740733910330138582, 100732508251634749738002515251900185798485578709518688083838565500932099246055)
s_message = ""
host = socket.gethostname()
port = 8808
client = socket.socket()
client.connect((host, port))
s_cipher = to_binary(en_method)
client.send(s_cipher.encode())
r_cipher = client.recv(1024).decode()
r_cipher = nonce_inc(r_cipher)
r_cipher = nonce_inc(r_cipher)
r_cipher = nonce_inc(r_cipher)
r_cipher = nonce_inc(r_cipher)
s_cipher = to_binary(r_cipher)
client.send(s_cipher.encode())
##
cypher = client.recv(10240).decode()
dec = koblitz_de_str(cypher,pri)
r_cipher = nonce_inc(dec)
s_cipher = to_binary(r_cipher)
client.send(s_cipher.encode())

#sec1  = client.recv(10240).decode()
#sec1 = koblitz_de(sec1, pri)
#sec2  = client.recv(10240).decode()
#sec2 = koblitz_de(sec2, pri)
#sec3  = client.recv(10240).decode()
#sec3 = koblitz_de(sec3, pri)

#print(sec1,sec2,sec3)

print("SSL handshake complete")


## NEED IMPLEMENTATION #########################################
## need exchange before the actual communication
CLIENT_ENCKEY =  (57347989155196480278832323052921971267628012422077849954342099867867099811588, 5737424824561123120621740469216300061329422523941799479443051959145616940579)
CLIENT_DECKEY = 4968098174954198194808929959705034417145300753381397683341648479118799125144
MAC_KEY = "MACKEY"
## END ###########################################################


while s_message != "exit":
    s_message = input(">>> ")
    print("Sending: "+s_message)
    s_message = encryptor(en_method, s_message, MAC_KEY, CLIENT_ENCKEY)    
    s_cipher = to_binary(s_message)
    client.send(s_cipher.encode())
    
    r_cipher = client.recv(10240).decode()
    r_message = decryptor(en_method,r_cipher, MAC_KEY, CLIENT_DECKEY)
    print(r_message)
    if(r_message == "Goodbye!"):
        break
client.close()
