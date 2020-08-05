import socket
from Algorithms import *


server = socket.socket()
host = socket.gethostname()
port = 8808
server.bind((host, port))
server.listen(5)
message = ""
connect, addr = server.accept()
print("address: ", addr)
print(cipher)
while message != "exit":
    cipher = connect.recv(1024).decode()

    message = to_string(cipher)
    print(message)
connect.close()
server.close()
