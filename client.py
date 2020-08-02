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


message = ""

host = socket.gethostname()
port = 8808
while message != "exit":
    client = socket.socket()
    client.connect((host, port))
    message = input(">>> ")
    client.send(to_binary(message).encode())
    client.close()
