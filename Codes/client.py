import socket
from KEYgen import *
from Algorithms import *
from ECCryp import *
from IntegratedEnDecryptor import *


en_method = input("Enter the encryption method (ELG/ECC/DES) you want: ")
if en_method != "ELG" and en_method != "ECC" and en_method != "DES":
    en_method = "ELG"
pri, pub =  101375943321386149405255896770276173339493063286505907504133666719784558836801, \
           (46745410170763116639558389851576751376301611910273696710697654476131960007936, 99310026869934149626916933043616231052578698302535499877622520030423328957386)
srd = 28163497231646330096955240836392597663982077794570507527227719278559069711492
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

r_cipher = client.recv(200240).decode()
r_message = to_string(CBC_DES_decrypt(r_cipher, (to_binary(str(srd))[:64],to_binary(str(srd))[64:128])))
# print(r_message)
keys = r_message.split(",")
if en_method == "ELG":
    CLIENT_ENCKEY = [int(keys[0]), int(keys[1]), int(keys[2])]
    CLIENT_DECKEY = [int(keys[3]), int(keys[4]), int(keys[5])]
elif en_method == "DES":
    CLIENT_ENCKEY = [keys[0], keys[1]]
    CLIENT_DECKEY = [keys[2], keys[3]]
elif en_method == "ECC":
    CLIENT_ENCKEY = (int(keys[0]), int(keys[1]))
    CLIENT_DECKEY = int(keys[2])
# print(CLIENT_DECKEY,CLIENT_ENCKEY)
MAC_KEY = keys[-1]
print("SSL handshake complete")

# print(CLIENT_DECKEY)
# print(CLIENT_ENCKEY)
# print(MAC_KEY)

while s_message != "exit":
    s_message = input(">>> ")
    s_message = str(s_message)
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
