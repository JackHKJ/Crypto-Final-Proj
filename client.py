import socket
from Algorithms import *

message = ""
host = socket.gethostname()
port = 8808
while message != "exit":
    client = socket.socket()
    client.connect((host, port))
    message = input(">>> ")
    client.send(to_binary(message).encode())
    client.close()
