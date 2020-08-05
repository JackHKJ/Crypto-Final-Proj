import socket
from Algorithms import *

message = ""
host = socket.gethostname()
port = 8808
client = socket.socket()
client.connect((host, port))
while message != "exit":

    message = input(">>> ")
    client.send(to_binary(message).encode())
client.close()
