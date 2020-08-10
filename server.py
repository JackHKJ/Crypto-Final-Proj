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
pri, pub = 24540860894901296002106611197692978439986639389673598864824915546895243523884, \
           (64991997441828919360060966063558821932645220918997486358754929826725776010518, 66758789698114878663337548137288305612963497731817000763542851027671642700936)
srd = 28163497231646330096955240836392597663982077794570507527227719278559069711492
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
r_message = koblitz_de_str(r_cipher, pri)
en_method = r_message
nce = nonce_new(en_method)
s_cipher = koblitz_en_str(nce, pub)
connect.send(s_cipher.encode())
r_cipher = connect.recv(1024).decode()
r_message = koblitz_de_str(r_cipher, pri)
tmpnce = nce
for i in range(4):
    tmpnce = nonce_inc(tmpnce)
if tmpnce != r_message:
    print("Handshake failed! @nce Closing connection {}".format(addr))
    connect.close()
    exit()
nce = nonce_inc(nce)
tmpnce = nonce_inc(nce)
tclnt = koblitz_en_str(nce, pub)
checkp = koblitz_en(tmpnce, pub)
##
connect.send(tclnt.encode())
r_cipher = connect.recv(10240).decode()

r_message = to_string(r_cipher)
if r_message != tmpnce:
    print(r_cipher, checkp)
    print("Handshake failed! @dec Closing connection {}".format(addr))
    connect.close()
    exit()

# generating key pairs for encryption
if en_method == "ELG":
    SERVER_ENCKEY, CLIENT_DECKEY = KeyGen()
    CLIENT_ENCKEY, SERVER_DECKEY = KeyGen()
    s_message = str(CLIENT_ENCKEY[0]) + "," + str(CLIENT_ENCKEY[1]) + "," + str(CLIENT_ENCKEY[2]) + "," + \
                str(CLIENT_DECKEY[0]) + "," + str(CLIENT_DECKEY[1]) + "," + str(CLIENT_DECKEY[2]) + ","
elif en_method == "DES":
    SERVER_ENCKEY = CLIENT_DECKEY = keygen()
    CLIENT_ENCKEY = SERVER_DECKEY = keygen()
    s_message = str(CLIENT_ENCKEY[0]) + "," + str(CLIENT_ENCKEY[1]) + "," + \
                str(CLIENT_DECKEY[0]) + "," + str(CLIENT_DECKEY[1]) + ","
elif en_method == "ECC":
    CLIENT_DECKEY, SERVER_ENCKEY = make_keypair()
    SERVER_DECKEY, CLIENT_ENCKEY = make_keypair()
    s_message = str(CLIENT_ENCKEY[0]) + "," + str(CLIENT_ENCKEY[1]) + "," + str(CLIENT_DECKEY)
MAC_KEY = random.randint(2**62, 2**63)


s_message += str(MAC_KEY)

s_cipher = CBC_DES_encrypt(to_binary(s_message), (to_binary(str(srd))[:64],to_binary(str(srd))[64:128]))
connect.send(s_cipher.encode())


# sec1 = str(CLIENT_DECKEY)
# sec1 = koblitz_en(sec1, pub)
# print(sec1)
# connect.send(sec1.encode())
# sec2 = str(CLIENT_ENCKEY)
# sec2 = koblitz_en(sec2, pub)
# connect.send(sec1.encode())
# sec3 = str(MAC_KEY)
# sec3 = koblitz_en(sec3, pub)
# connect.send(sec1.encode())

print("SSL handshake complete")


while r_message != "exit":
    r_cipher = connect.recv(10240).decode()
    r_message = to_string(r_cipher)
    r_message = decryptor(en_method, r_message, MAC_KEY, SERVER_DECKEY)
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
