import socket
from KEYgen import ECCsrv
from Algorithms import *
from ECCryp import *
from ElGamal import *
from MACer import *
from IntegratedEnDecryptor import *
"""
SSL handshake protocol
1. client: Choice of 'ECC', 'DES', 'ELG'
2. server: nonce
3. client: nonce+4
4. server: nonce+2
5. client: E(nonce+5)
6. server: E(secret)
7. client: Esec(message)
"""

       


en_method = "ELG"
#KEYS GOES HERE, TESTING ONLY!!!
pri, pub = 17266110910292182863031101798374952031947451314643790344773650325784057863506, (63418887483913902302210242333028958573736406591311866468970740733910330138582, 100732508251634749738002515251900185798485578709518688083838565500932099246055)

secret = 'hello'
balance = 100.00
server = socket.socket()
host = socket.gethostname()
port = 8808
server.bind((host, port))
server.listen(5)
r_message = ""
connect, addr = server.accept()
print("address: ", addr)


#r_cipher = connect.recv(1024).decode()
#r_message = to_string(r_cipher)
#en_method = r_message
#nce = nonce_new(en_method)
#connect.send(nce.encode())
#r_cipher = connect.recv(1024).decode()
#r_message = to_string(r_cipher)
#tmpnce = nonce_inc(nce)
#tmpnce = nonce_inc(tmpnce)
#tmpnce = nonce_inc(tmpnce)
#tmpnce = nonce_inc(tmpnce)

#if(tmpnce != r_message):
    #print("Handshake failed! @nce Closing connection {}".format(addr))
    #connect.close()
    #exit()
#nce = nonce_inc(nce)
#tmpnce = nonce_inc(nce)
#tclnt = koblitz_en(nce, pub)
#checkp = koblitz_en(tmpnce,pub)

#connect.send(str(tclnt[0][0]).encode())
#r_cipher = connect.recv(1024).decode()
#connect.send(str(tclnt[0][1]).encode())
#r_cipher = connect.recv(1024).decode()
#connect.send(str(tclnt[1][0]).encode())
#r_cipher = connect.recv(1024).decode()
#connect.send(str(int(tclnt[1][1])).encode())
#r_cipher = connect.recv(1024).decode()
#r_message = to_string(r_cipher)
#if r_message != tmpnce:
    #print(r_cipher,checkp)
    #print("Handshake failed! @dec Closing connection {}".format(addr))
    #connect.close()
    #exit()
#connect.send('secret'.encode())
#print("SSL handshake complete")

## NEED IMPLEMENTATION #########################################
## need exchange before the actual communication
SERVER_ENCKEY = [2632130759, 1036786760, 1316040819]
SERVER_DECKEY = [3521483783, 104390050, 1087869608]
MAC_KEY = "MACKEY"
## END ###########################################################

#if en_method == "ELG":
    #pass
    ##ElGamal private and public key generation
#else:
    #pri, pub = make_keypair()# key gen for int pri, tuple (int , int) pub

while r_message != "exit":
    r_cipher = connect.recv(10240).decode()
    r_message = to_string(r_cipher)
    
    ## decrypt here
    #if en_method == "ECC":
        #pass
        ##encrypt with ECC
    #elif en_method == "DES":
        #pass
        ##encrypt with DES
    #elif en_method == "ELG":
        #pass
        ##encrypt with ELG
    r_message = decryptor(en_method,r_message,MAC_KEY,SERVER_DECKEY)    
    print("<<<", r_message)
    
    command = r_message.split()
    s_message = ""
    if command[0] == "deposit":
        if len(command) != 2:
            s_message = "Invalid command!\nSee commands using \"help\""
        elif command[1].isnumeric():
            balance += float(command[1])
            s_message = "Successfully deposited ${}".format(command[1])
    elif command[0] == "withdraw":
        if len(command) != 2:
            s_message = "Invalid command!\nSee commands using \"help\""
        elif command[1].isnumeric():
            if float(command[1]) > balance:
                s_message = "Not enough balance!".format(command[1])
            else:
                balance -= float(command[1])
                s_message = "Successfully withdrew ${}".format(command[1])
    elif command[0] == "balance":
        s_message = "Balance: ${}".format(balance)
    elif command[0] == "hello":
        s_message = "hello"
    elif command[0] == "exit":
        s_message = "Goodbye!"
    elif command[0] == "help":
        s_message = "Deposit: deposit (amount)\n" \
                    "Withdraw: withdraw (amount)\n" \
                    "Check Balance: balance\n" \
                    "Exit: exit"
    else:
        s_message = "Invalid command!\nSee commands using \"help\""
    # encrypt here
    print("sending message: "+s_message)
    s_cipher = encryptor(en_method,s_message,MAC_KEY,SERVER_ENCKEY)      
    connect.send(s_cipher.encode())
connect.close()
server.close()
