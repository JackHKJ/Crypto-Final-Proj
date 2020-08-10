import hashlib
import hmac
import math
import random
from StringBinaryConverter import *


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
    key = b'114514'
    h = hmac.new(key, string, digestmod='MD5')
    return h


# initial permutation
def IP(plain):
    order = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
             62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
             57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
             61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
    cipher = ""
    for i in range(64):
        cipher += plain[order[i] - 1]
    return cipher


# inverse initial permutation
def IIP(plain):
    order = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
             38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
             36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
             34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,  49, 17, 57, 25]
    cipher = ""
    for i in range(64):
        cipher += plain[order[i] - 1]
    return cipher


# expansion function for plain text
def Expansion(plain):
    order = [32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,  8,  9,  10, 11,
             12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
             22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
    cipher = []
    for i in range(48):
        cipher.append(plain[order[i] - 1])
    return cipher


# reduction function for key
def reduction56(key):
    order = [57, 49, 41, 33, 25, 17, 9,  1,
             58, 50, 42, 34, 26, 18, 10, 2,
             59, 51, 43, 35, 27, 19, 11, 3,
             60, 52, 44, 36, 63, 55, 47, 39,
             31, 23, 15, 7,  62, 54, 46, 38,
             30, 22, 14, 6,  61, 53, 45, 37,
             29, 21, 13, 5,  28, 20, 12, 4]
    key56 = ""
    for i in range(56):
        key56 += key[order[i] - 1]
    return key56


# reduction function for key
def reduction48(key):
    order = [14, 17, 11, 24, 1,  5,  3,  28,
             15, 6,  21, 10, 23, 19, 12, 4,
             26, 8,  16, 7,  27, 20, 13, 2,
             41, 52, 31, 37, 47, 55, 30, 40,
             51, 45, 33, 48, 44, 49, 39, 56,
             34, 53, 46, 42, 50, 36, 29, 32]
    key48 = ""
    for i in range(48):
        key48 += key[order[i] - 1]
    return key48


# on iteration i, left shift order[i] bits
def left_shift(key, round):
    order = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    lkey = key[:28]
    rkey = key[28:56]
    for i in range(order[round]):
        lkey = lkey[1:28] + lkey[0]
        rkey = rkey[1:28] + rkey[0]
    return lkey + rkey


# switch function for sbox
def switch(plain):
    order = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
             2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
    cipher = []
    for i in range(32):
        cipher.append(plain[order[i] - 1])
    return cipher


# sbox 1 to 8
def sbox(plain):
    box = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
            [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
             [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
             [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
             [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
            [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
             [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
             [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
             [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
            [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
             [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
             [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
             [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
            [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
             [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
             [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
             [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
            [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
             [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
             [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
             [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
            [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
             [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
             [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
             [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
            [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
             [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
             [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
             [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
    cipher = ""
    for i in range(8):
        row = int(plain[i*6] + plain[i*6+5], 2)
        col = int(plain[i*6+1] + plain[i*6+2] + plain[i*6+3] + plain[i*6+4], 2)
        s = bin(box[i][row][col])[2:]
        s = "0"*(4-len(s)) + s
        cipher += s
    cipher = switch(cipher)
    return cipher


# encrypt function for DES
def DES_encrypt(plain, key):
    plain = IP(plain)
    keys = []
    key = reduction56(key)
    for i in range(16):
        key = left_shift(key, i)
        keys.append(reduction48(key))
    left = plain[0:32]
    right = plain[32:64]
    for i in range(16):
        f = sbox(xor(Expansion(right), keys[i]))
        left1 = right
        right1 = xor(left, f)
        left = left1
        right = right1
    cipher = IIP(right + left)
    return cipher


# decrypt function for DES
def DES_decrypt(cipher, key):
    cipher = IP(cipher)
    keys = []
    key = reduction56(key)
    for i in range(16):
        key = left_shift(key, i)
        keys.append(reduction48(key))
    left = cipher[0:32]
    right = cipher[32:64]
    for i in range(16):
        f = sbox(xor(Expansion(right), keys[15 - i]))
        left1 = right
        right1 = xor(left, f)
        left = left1
        right = right1
    plain = IIP(right + left)
    return plain


def CBC_DES_encrypt(plain, keys):
    plain = Encoder64(plain)
    key = keys[0]
    iv = keys[1]
    blocks = math.ceil(len(plain) / 64)
    if blocks == 1:
        return DES_encrypt(xor(plain, iv), key)
    else:
        plains = []
        for i in range(blocks):
            plains.append(plain[i*64:(i+1)*64])
        ciphers = [DES_encrypt(xor(plains[0], iv), key)]
        cipher = ""
        for i in range(1, blocks):
            ciphers.append(DES_encrypt(xor(plains[i], ciphers[i-1]), key))
        for i in range(blocks):
            cipher += ciphers[i]
        return cipher


def CBC_DES_decrypt(cipher, keys):
    key = keys[0]
    iv = keys[1]
    blocks = math.ceil(len(cipher) / 64)
    if blocks == 1:
        plain =  xor(DES_decrypt(cipher, key), iv)
        return Decoder64(plain)
    else:
        ciphers = []
        for i in range(blocks):
            ciphers.append(cipher[i*64:(i+1)*64])
        plains = [xor(DES_decrypt(ciphers[0], key), iv)]
        plain = ""
        for i in range(1, blocks):
            plains.append(xor(DES_decrypt(ciphers[i], key), ciphers[i-1]))
        for i in range(blocks):
            plain += plains[i]
        plain = Decoder64(plain)
        return plain


def stohx (a):
    return "".join("{:02x}".format(ord(c)) for c in a)


def hxtos (a):
    return bytearray.fromhex(a).decode()


def hxtoi (a):
    return int(a,16)


def itohx(a):
  return hex(a)[2:]


def nonce_new(enc):
    a = str(hxtoi(stohx(enc)))[:16]
    if 16 != len(a):
        for i in range(16):
            if len(a)==16:
                break
            a = a[-i] + a
    return a


def nonce_inc(a):
    tmp = 16
    a = str(int(a[4:]+a[1]+a[3]+a[0]+a[2])+5)
    if tmp != len(a):
        for i in range(tmp):
            if len(a)==tmp:
                break
            a = a[-i] + a
    return a


def keygen():
    des_key = bin(random.randint(1, 2 ** 64))[2:]
    des_key = "0"*(64-len(des_key)) + des_key
    cbc_iv = bin(random.randint(1, 2 ** 64))[2:]
    cbc_iv = "0"*(64-len(cbc_iv)) + cbc_iv
    return [des_key, cbc_iv]

# a = nonce_new("ECC")
# for i in range(20):
#     print(a)
#     a = nonce_inc(a)
