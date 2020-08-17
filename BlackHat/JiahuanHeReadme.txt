In their handshake protocol, there is no nonce exchange, which makes Replay Attack and Man-in-the-Middle Attack
extremely effective.
At first, The server sends a message of its status and the client receives it to start the handshake
server.py: 123 | self.send_message(sock, OK_START_KEY_EXCHANGE, encrypted=False)
client.py: 82  | error, message = self.receive_message(encrypted=False)

Next, client generates a Diffie-Hellman message and sends it to the server IN PLAIN TEXT
client.py: 92  | dh_step_1 = pow(DIFFIE_HELLMAN_PUBLIC_G, DIFFIE_HELLMAN_SECRET_RANDOM_CLIENT, DIFFIE_HELLMAN_PUBLIC_N)
client.py: 94  | self.send_message(format_diffie_hellman_message(dh_step_1), encrypted=False)

Then, The server receives the message and later generates the session key with it
server.py: 125 | error, dh_step_1_raw = self.receive_message(sock, encrypted=False, buffer_size=1500)
server.py: 138 | self.session_key = pow(dh_step_2, DIFFIE_HELLMAN_SECRET_RANDOM_CLIENT, DIFFIE_HELLMAN_PUBLIC_N)

Likely, The server generates a Diffie-Hellman message and sends it to the client too, also IN PLAIN TEXT
server.py: 135 | dh_step_2 = pow(DIFFIE_HELLMAN_PUBLIC_G, DIFFIE_HELLMAN_SECRET_RANDOM_SERVER, DIFFIE_HELLMAN_PUBLIC_N)
server.py: 136 | self.send_message(sock, format_diffie_hellman_message(dh_step_2), encrypted=False)

Next, The client receives the message and generates its key
client.py: 101 | error, dh_step_2_raw = self.receive_message(encrypted=False, buffer_size=1500)
client.py: 108 | self.session_key = pow(dh_step_2, DIFFIE_HELLMAN_SECRET_RANDOM_CLIENT, DIFFIE_HELLMAN_PUBLIC_N)

Finally, The client and the server sends their status and complete the handshake if everything is alright
client.py: 111 | self.send_message(OK_START_SESSION_REQ, encrypted=True)
client.py: 112 | error, session_start_res = self.receive_message(encrypted=True)
server.py: 142 | error, session_start_req = self.receive_message(sock, encrypted=True)
server.py: 149 | self.send_message(sock, OK_START_SESSION_RES, encrypted=True)


As we can see, the only part encrypted in the handshake is the final status exchange, which contains nothing important.
Since there is no nonce exchange, it is impossible for the server to make sure that it's communicating with the real
client. So we can record the message and replay it or intercept the message and perform a Man-in-the-Middle Attack.

For the receive function, only server verifies MAC, while the client checks a digital signature that is in the first
half of the message, separated with "|", which makes it vulnerable to Man-in-the-Middle Attack by simply connecting the
message we want the client to see with the server's signature.
server.py: 114 | if encrypted:
server.py: 115 | 	assert(sock in self.session_keys)
server.py: 116 | 	message, verified = SymmetricEncryption.decrypt(message, self.session_keys[sock])
server.py: 117 | 	if not verified:
server.py: 118 | 		return 'MAC does not match!', None
client.py: 53  | DigitalSignature.verify(message, signature, SERVER_SIGNING_PUBLIC_KEY)


For example, suppose the client's key is c, the server's key is s and our, the man in the middle's, key is m. In the
beginning of handshake, the client and server exchanges their status to make sure that the server is able to handle the
connection, we simply let the message to be sent to the other side. Next, the client sends a message generated with
Diffie-Hellman, C = g ^ c % p, from here, we intercept the communication, and send our message M = g ^ m % p to the
server and the client. Then, receive the server's respond S = g ^ s % p. Now, the key between the client and us is
Kc = C ^ m % p = g ^ (c * m) % p and the key between the server and us is Ks = M ^ s % p = g ^ (s * m) % p. The server
and the client both thinks they share the same key but actually only we can decrypt the message. From now on, the
connection is under our control, we can replay the client's message and even fake the server's message since the client
doesn't check MAC. For instance, since we can decrypt the client's message, we can record the message the client sent,
such as "deposit 1000" and send it to the server multiple times, and send the message we want the client to see with the
signature cut from server's message.


