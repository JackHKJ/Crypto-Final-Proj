padding_list = ["!","@","#","$","%","^","&","*","(",")","_","+",",",".","<",">","?",";",":","[","]","{","}"]
import random

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
    for i in range(int(len(binary) // 8)):
        string += chr(int(binary[i*8:i*8+8], 2))
    return string

def Encoder32(message):
    message = str(message)
    if(len(message)%4 != 0):
        itr = len(message) %4
        for i in range(itr):
            message += padding_list[random.randint(0,len(padding_list)-1)]
    return to_binary(message)

def Decoder32(message):
    ret = to_string(message)
    while(ret[-1] in padding_list):
        ret = ret[:-1]
    return ret


def Encoder64(message):
    if(len(message)%8 != 0):
        for i in range(len(message)%8):
            message += padding_list[random.randint(0,len(padding_list)-1)]
    return to_binary(message)

def Decoder64(message):
    ret = to_string(message)
    while(ret[-1] in padding_list):
        ret = ret[:-1]
    return ret

#def padding64(message):
    #message = str(message)
    #while(len(message)%64 != 0):
        #message += padding_list[random.randint(0,len(padding_list)-1)]    
    #return message

#def dePadding64(message):
    #ret = to_string(message)
    #while(ret[-1] in padding_list):
        #ret = ret[:-1]
    #return ret    