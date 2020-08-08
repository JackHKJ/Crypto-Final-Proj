import socket
from KEYgen import *
from Algorithms import *
from ECCryp import *

en_method = "ECC"
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
r1 = client.recv(1024).decode()
client.send(s_cipher.encode())
r2 = client.recv(1024).decode()
client.send(s_cipher.encode())
r3 = client.recv(1024).decode()
client.send(s_cipher.encode())
r4 = client.recv(1024).decode()
cyph = ((int(r1),int(r2)),(int(r3),float(r4)))
dec = koblitz_de(cyph,pri)
r_cipher = nonce_inc(dec)
s_cipher = to_binary(r_cipher)
client.send(s_cipher.encode())
r_cipher = client.recv(1024).decode()#serect, need decrypt
print("SSL handshake complete")
while s_message != "exit":
    s_message = input(">>> ")
    s_cipher = to_binary(s_message)
    client.send(s_cipher.encode())
    r_cipher = client.recv(1024).decode()
    r_message = r_cipher
    print(r_message)
client.close()
