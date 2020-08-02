import hashlib
import hashlib
import hmac


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


def xor(a, b):
    if len(a) != len(b):
        print("ERROR: length not equal!")
    temp = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            temp += "0"
        else:
            temp += "1"
    return temp


def SHA1(string):
    sha = hashlib.sha1(string.encode('utf-8'))
    return sha


def HMAC(string):
    h = hmac.new(string, digestmod='MD5')
    return h
