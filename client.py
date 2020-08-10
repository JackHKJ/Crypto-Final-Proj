import socket
from KEYgen import *
from Algorithms import *
from ECCryp import *
from IntegratedEnDecryptor import *


en_method = input("Enter the encryption method (ELG/ECC/DES) you want: ")
if en_method != "ELG" and en_method != "ECC" and en_method != "DES":
    en_method = "ELG"
pri, pub = 17266110910292182863031101798374952031947451314643790344773650325784057863506, \
           (63418887483913902302210242333028958573736406591311866468970740733910330138582,
            100732508251634749738002515251900185798485578709518688083838565500932099246055)
s_message = ""
host = socket.gethostname()
port = 8808
client = socket.socket()
client.connect((host, port))
s_cipher = koblitz_en_str(en_method, pub)
client.send(s_cipher.encode())
r_cipher = client.recv(1024).decode()
r_message = koblitz_de_str(r_cipher, pri)
nonce = r_message
for i in range(4):
    nonce = nonce_inc(nonce)
s_cipher = koblitz_en_str(nonce, pub)
client.send(s_cipher.encode())
##
cypher = client.recv(10240).decode()
dec = koblitz_de_str(cypher, pri)
s_cipher = nonce_inc(dec)
s_cipher = to_binary(s_cipher)
client.send(s_cipher.encode())

# sec1  = client.recv(10240).decode()
# sec1 = koblitz_de(sec1, pri)
# sec2  = client.recv(10240).decode()
# sec2 = koblitz_de(sec2, pri)
# sec3  = client.recv(10240).decode()
# sec3 = koblitz_de(sec3, pri)
# print(sec1,sec2,sec3)

r_cipher = client.recv(1024).decode()
r_message = to_string(CBC_DES_encrypt(r_cipher, (to_binary(str(pri))[:64],to_binary(str(pri))[64:128])))
print(r_message)
keys = r_message.split(",")
if en_method == "ELG":
    CLIENT_ENCKEY = [keys[0], keys[1], keys[2]]
    CLIENT_DECKEY = [keys[3], keys[4], keys[5]]
elif en_method == "DES":
    CLIENT_ENCKEY = [keys[0], keys[1]]
    CLIENT_DECKEY = [keys[2], keys[3]]
elif en_method == "ECC":
    CLIENT_ENCKEY = [keys[0], keys[1]]
    CLIENT_DECKEY = keys[2]
MAC_KEY = keys[-1]
print("SSL handshake complete")


while s_message != "exit":
    s_message = input(">>> ")
    print("Sending: "+s_message)
    s_message = encryptor(en_method, s_message, MAC_KEY, CLIENT_ENCKEY)    
    s_cipher = to_binary(s_message)
    client.send(s_cipher.encode())
    
    r_cipher = client.recv(10240).decode()
    r_message = decryptor(en_method,r_cipher, MAC_KEY, CLIENT_DECKEY)
    print(r_message)
    if r_message == "Goodbye!":
        break
client.close()
