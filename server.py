import socket
from Algorithms import *


balance = 100.00
server = socket.socket()
host = socket.gethostname()
port = 8808
server.bind((host, port))
server.listen(5)
r_message = ""
connect, addr = server.accept()
print("address: ", addr)
while r_message != "exit":
    r_cipher = connect.recv(1024).decode()
    # decrypt here
    r_message = to_string(r_cipher)
    print("<<<", r_message)
    command = r_message.split()
    if command[0] == "deposit":
        if len(command) != 2:
            s_message = "Invalid command!"
            # encrypt here
            s_cipher = s_message
            connect.send(s_cipher.encode())
        elif command[1].isnumeric():
            balance += float(command[1])
            s_message = "Successfully deposited ${}".format(command[1])
            # encrypt here
            s_cipher = s_message
            connect.send(s_cipher.encode())
    elif command[0] == "withdraw":
        if len(command) != 2:
            s_message = "Invalid command!"
            # encrypt here
            s_cipher = s_message
            connect.send(s_cipher.encode())
        elif command[1].isnumeric():
            if float(command[1]) > balance:
                s_message = "Not enough balance!".format(command[1])
                # encrypt here
                s_cipher = s_message
                connect.send(s_cipher.encode())
            else:
                balance -= float(command[1])
                s_message = "Successfully withdrew ${}".format(command[1])
                # encrypt here
                s_cipher = s_message
                connect.send(s_cipher.encode())
    elif command[0] == "balance":
        s_message = "Balance: ${}".format(balance)
        # encrypt here
        s_cipher = s_message
        connect.send(s_cipher.encode())
    elif command[0] == "hello":
        s_message = "hello"
        # encrypt here
        s_cipher = s_message
        connect.send(s_cipher.encode())
    elif command[0] == "exit":
        s_message = "Goodbye!"
        # encrypt here
        s_cipher = s_message
        connect.send(s_cipher.encode())
    elif command[0] == "help":
        s_message = "Deposit: deposit (amount)\n" \
                    "Withdraw: withdraw (amount)\n" \
                    "Check Balance: balance\n" \
                    "Exit: exit"
        # encrypt here
        s_cipher = s_message
        connect.send(s_cipher.encode())
    else:
        s_message = "Invalid command!\nSee commands using \"help\""
        # encrypt here
        s_cipher = s_message
        connect.send(s_cipher.encode())
connect.close()
server.close()
