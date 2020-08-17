1. Vulnerable plaintext output from  messages.py:extract_diffie_hellman_message().
Reasoning:
messages.py:11  |def extract_diffie_hellman_message(message):
messages.py:12  |   if not message.startswith('OK|DH1.') or not message[7:].isdigit():
messages.py:13  |		return None
messages.py:14  |	return int(message[7:])
                           ^^^^^^^^^^^^^^^^
             the input "messages" is based on f'OK|DH1.{num}'(messages.py:9)
messages.py:9   |	return f'OK|DH1.{num}'

These suggests that the server and the client's secure key exchange is based on the fact that "OK|DH1." is
in the beginning of the received shared secret, and "|" to denote MAC signing.

This practice is vulnerable because it tells the Black Hat two things:
        1. Plain text is transmitted during the protocol, which ensures all or some parts of the handshake are not encrypted.
        2. Which part is the shared secret, and can be swapped for sabotage.
    The fact that the handshake is not encrypted is already posing danger to the client, but ensuring that the
protocol is not encrypted is a way to signal to the man-in-the-middle that the handshake can be manipulated.
Leaving the first 7 bytes and only sending the shared secret can be better this, leaving the Black Hat guessing whether
or not the protocol is encrypted and what encryption is it using.
It also suggests the other handshake protocols are not encrypted, even if the black hat doesn't have the source code.
    Since this is automated handshake, even if the whole handshake protocol is encrypted, plaintext during handshake is
adding extra unnecessary workload to the encryption algorithm and can be inefficient.


2.  Weak or useless nonce, "message_no".
Reasoning:
    Structure of the general messages from the client:
    AES("OK|{username}.{password}|{message_no}|{type}.{arg1}.+{arg2}.+....{argn}}"|MAC())

    "message_no" is formed in
client.py:70 |		self.message_no = 0
    and incremented by 2 in
client.py:225|			self.message_no+=2
    checked by server in:
server.py:183|		if message_no != self.message_numbers[sock]:
server.py:184|			print(f'{format_peername(sock)}: error unexpected message number (got {message_no} but was expecting {self.message_numbers[sock]})')
server.py:185|			self.send_message(sock, 'unexpected message number', message_no=self.message_numbers[sock] + 1)
server.py:186|			return False

    The Black Hat can increment the message_no by themselves by +2.
    If the message is intercepted and decrypted, the Black Hat can still pretend to be the client since the nonce doesn't
need special functions. A more rigorous nonce would need server or the client to increment it and not by anyone else.



How to attack:
    Since the plaintext tells the Black Hat which part of the message is the shared secret, a Black Hat can open another
     connection with the server and send the generated key,k formated as "OK|DH1."+k to the server.
    Nonce offered little to no security advantage than not having it.





