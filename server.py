import socket
from Algorithms import *


server = socket.socket()
host = socket.gethostname()
port = 8808
server.bind((host, port))
server.listen(5)
message = ""
while message != "exit":
    connect, addr = server.accept()
    cipher = connect.recv(1024).decode()
    print("address：", addr)
    print(cipher)
    message = to_string(cipher)
    print(message)
    connect.close()
server.close()
