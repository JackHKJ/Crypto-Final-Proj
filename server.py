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
# KEYS GOES HERE, TESTING ONLY!!!
pri, pub = 17266110910292182863031101798374952031947451314643790344773650325784057863506, \
           (63418887483913902302210242333028958573736406591311866468970740733910330138582,
            100732508251634749738002515251900185798485578709518688083838565500932099246055)

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


r_cipher = connect.recv(1024).decode()
r_message = to_string(r_cipher)
en_method = r_message
nce = nonce_new(en_method)
connect.send(nce.encode())
r_cipher = connect.recv(1024).decode()
r_message = to_string(r_cipher)
tmpnce = nonce_inc(nce)
tmpnce = nonce_inc(tmpnce)
tmpnce = nonce_inc(tmpnce)
tmpnce = nonce_inc(tmpnce)

if(tmpnce != r_message):
    print("Handshake failed! @nce Closing connection {}".format(addr))
    connect.close()
    exit()
nce = nonce_inc(nce)
tmpnce = nonce_inc(nce)
tclnt = koblitz_en_str(nce, pub)
checkp = koblitz_en(tmpnce,pub)
##
connect.send(tclnt.encode())
r_cipher = connect.recv(10240).decode()


r_message = to_string(r_cipher)
if r_message != tmpnce:
    print(r_cipher,checkp)
    print("Handshake failed! @dec Closing connection {}".format(addr))
    connect.close()
    exit()
    
## generating key pairs for encryption
if en_method == "ELG":
    SERVER_ENCKEY, CLIENT_DECKEY = KeyGen()
    CLIENT_ENCKEY, SERVER_DECKEY = KeyGen()
if en_method == "DES":
    SERVER_ENCKEY = CLIENT_DECKEY = keygen()
    CLIENT_ENCKEY = SERVER_DECKEY = keygen()
## todo ECC

MAC_KEY = random.randint(2**62, 2**63)

#sec1 = str(CLIENT_DECKEY)
#sec1 = koblitz_en(sec1, pub)
#print(sec1)
#connect.send(sec1.encode())

#sec2 = str(CLIENT_ENCKEY)
#sec2 = koblitz_en(sec2, pub)
#connect.send(sec1.encode())

#sec3 = str(MAC_KEY)
#sec3 = koblitz_en(sec3, pub)
#connect.send(sec1.encode())


print("SSL handshake complete")

## NEED IMPLEMENTATION #########################################
## need exchange before the actual communication
SERVER_ENCKEY = (111424227728653973693487741115936850362795211037851575928498626423329976428198, 11142569238708697687739565437964320833265344920279491677967914583507687303629)
SERVER_DECKEY = 91838603497381221099410955303817289674795061747944840649439772219237063007634
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
            s_message = "Invalid command!\nthe right format should be: withdraw {amount}"
        elif command[1].isnumeric():
            if float(command[1]) > balance:
                s_message = "Not enough balance!".format(command[1])
            else:
                balance -= float(command[1])
                s_message = "Successfully withdrew ${}".format(command[1])
        else:
            s_message = "Invalid command!\nthe amount should be a number"
    elif command[0] == "balance":
        s_message = "Balance: ${}".format(balance)
    elif command[0] == "hello":
        s_message = "hello"
    elif command[0] == "exit":
        s_message = "Goodbye!"
    elif command[0] == "help":
        s_message = "Deposit: deposit {amount}\n" \
                    "Withdraw: withdraw {amount}\n" \
                    "Check Balance: balance\n" \
                    "Exit: exit"
    else:
        s_message = "Invalid command!\nSee commands using \"help\""
    # encrypt here
    print("sending message: "+s_message)
    s_cipher = encryptor(en_method, s_message, MAC_KEY, SERVER_ENCKEY)
    connect.send(s_cipher.encode())
connect.close()
server.close()
