import socket


def to_binary(string):
    temp = []
    result = ""
    for i in range(len(string)):
        temp.append(bin(ord(string[i]))[2:9])
    for i in range(len(temp)):
        result += "0" * (8 - len(temp[i])) + temp[i]
    return result


def to_string(binary):
    string = ""
    for i in range(int(len(binary) / 8)):
        string += chr(int(binary[i*8:i*8+8], 2))
    return string


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
