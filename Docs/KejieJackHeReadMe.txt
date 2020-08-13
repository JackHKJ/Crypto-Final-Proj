
El Gamal implementation:

	This version of the El Gamal implementation uses the python random.randint module to generate desired (32bit) prime numbers, then find the primitive root and generate keygen to complete the actual implementation. 

	Details of implementation:
	1.prime number generation:
		a)generate a number between (2*30 to 2*31), which will eventually become 32 -bit format
		b)test whether the number is an actual prime
			if multiple of 2, reject,  go to a)
			if fails the solovay-strassen test[1], reject, goto a)
	2.calculate the primitive root of this number
	3.generate Keygen using the prime-number and its primitive root accompanied by a random number generated in the range
	4.use the keygen set to En/Decrypt

	[1] the S-S test checks the GCD of the target number and a randomly generated number, then checks the Jacobi symbol of two numbers in the derivation. The method that calculates the Jacobi symbol was first implemented in the way that we discussed in class, but it turns out to be having so bad recursive performances that python cannot handle. So I checked the rule of the Jacobi symbol and replace some recursive calls with special cases, which turn out to be much more efficient.

HMAC-SHA1 implementation:

	The MAC prototype and methodology were specified, therefore using Libraries provided on the net.
	Credit to the author: heskyji
	https://gist.github.com/heskyji/5167567b64cb92a910a3

	The logic of the Authentication is to add MAC (addMAC) to the end of the plain text and then encrypt the whole string, then check MAC (verifyMAC) when received. "$REJECT" will be returned as an ERROR message.

The StringBinaryConverter:

	This is a converter class implemented for add padding to satisfy the bit-length requirement, which uses the random padding that select characters in the set(padding_list) and append them to the end of the message. When decoding, strip off the characters from the back when possible

The NONCE implementation

	The nonce is integrated within the MAC function which generates a len 32 integer and append to the end of the message before the start of the encryption, then add the mac and then Encrypt the message:
	Enc((plain | NONCE ) | MAC) <- a structure like this
	two seperate files are used to store the NONCE of the server and the Client and will reject anytime a NONCE is reused