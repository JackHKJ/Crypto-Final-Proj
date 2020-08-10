ECC encryption implementation:
Encryption uses koblitz_en(m,ab) to add a message m into a point on the curve secp256k1, which is a widely used commercial-grade 256 bit curve. It has the benefit of being once the easiest to encrypt and one of the hardest to decrypt.
In detail, it scalar-multiples a random number onto a point on the curve with the message coded into the coordinates. This can be decoded with the key that is generated with the original point (generator).
With the special property of supporting scalar multiple, it makes a great public key encryption method. It is used in the SSL handshake where two pairs are multiplied and got a shared key.

SSL handshake:
The handshake verifies the client by exchanging encrypted nonce with random number, since each party has pre-communication shared public keys. If the above action is performed and checked by the server, the server generates and sends key pairs encryped with ECC for the communication.

Nonce:
For a secure nonce, it needs to be predictable for the parties with knowledge of how it changes, and yet unpredictable for the adversary (mostly man-in-the-middle). This is achieved by shifting multiple positions and incrementing some bytes.

