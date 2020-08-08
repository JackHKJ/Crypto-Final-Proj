import socket
from Algorithms import *

s_message = ""
host = socket.gethostname()
port = 8808
client = socket.socket()
client.connect((host, port))
while s_message != "exit":
    s_message = input(">>> ")
    s_cipher = to_binary(s_message)
    client.send(s_cipher.encode())
    r_cipher = client.recv(1024).decode()
    r_message = r_cipher
    print(r_message)
client.close()
