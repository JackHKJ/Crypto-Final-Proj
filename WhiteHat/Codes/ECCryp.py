import collections
import random
import binascii

#code curve is based on Standards for Efficient Cryptography Group

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)


def stohx(a):
    return "".join("{:02x}".format(ord(c)) for c in a)


def hxtos(a):
    return bytearray.fromhex(a).decode()


def hxtoi(a):
    return int(a,16)


def itohx(a):
    return hex(a)[2:]


# Modular arithmetic ##########################################################
# credit https://github.com/andreacorbellini/ecc/blob/master/scripts/ecdhe.py
def inverse_mod(k, p):
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    gcd, x, y = old_r, old_s, old_t
    assert gcd == 1
    assert (k * x) % p == 1
    return x % p


# Used to calculate Nb or Na times the point
def is_on_curve(point):
    if point is None:
        return True
    x, y = point
    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):
    assert is_on_curve(point)
    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result


# credit https://github.com/andreacorbellini/ecc/blob/master/scripts/ecdhe.py
def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result)

    return result


# credit https://github.com/andreacorbellini/ecc/blob/master/scripts/ecdhe.py
def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)
    k = int(k)
    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if int(k) & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result


def koblitz_en (m,ab):
    b = stohx(m)
    b = hxtoi(b)
    bet = ab
    tmpy = (b**3 + 7)**(1/2)
    rnum = random.randrange(1, curve.n)
    secr1 = scalar_mult( int(rnum), curve.g)
    tmp = scalar_mult( rnum, bet)
    secr2 =(b+tmp[0],tmpy+ tmp[1])
    return secr1, secr2


def make_keypair():
    private_key = random.randrange(1, curve.n)  # get a random number to multiply with
    public_key = scalar_mult(private_key, curve.g)
    return private_key, public_key


def koblitz_de(secr, ab):
    a = scalar_mult( ab, secr[0])
    b = (secr[1][0]-a[0], secr[1][1]-a[1])
    c = itohx(b[0])
    # print(ab)
    c = hxtos(c)
    return c


def koblitz_en_str(m, ab):
    cipherList = ""
    for i in range(0,len(m),35):
        cipherList += (str(koblitz_en(m[i:i+35], ab))) + "@"
        
    return cipherList


def koblitz_de_str(ciphertext, keyset):
    ret = ""
    sliced = ciphertext.split("@")
    for ciphertextslice in sliced:
        if len(ciphertextslice) == 0:
            break
        left, right = ciphertextslice[2:-2].split("), (")
        l1, l2 = left.split(", ")
        r1, r2 = right.split(", ")
        cipher = ((int(l1), int(l2)), (int(r1), float(r2)))
        ret += koblitz_de(cipher, keyset)
    return ret
    

# apr, apu = make_keypair()
# bpr, bpu = make_keypair()
# print(apr, apu)
# print(bpr, bpu)
# s1 = scalar_mult(apr, bpu)
# s2 = scalar_mult(bpr, apu)
# a = "ABCD1234wpbaKse4kCx8guvlqADTF-gkSLU="
# print(apr, apu)
# b = stohx(a)
# spri = s1[0]
# spub = scalar_mult(s1[0], curve.g)
# print("Encrypting: ",a)
# print("            ",b)
# b = koblitz_en(a,spub)
# print("Cypher: ",b)
# c = koblitz_de(b,spri)
# #
# print("A Decrypted: ",c)
if __name__ == "__main__":
    print('Curve:', curve.name)

    # Alice generates her own keypair.
    alice_private_key, alice_public_key = make_keypair()
    print("Alice's private key:", alice_private_key)
    print("Alice's public key: (0x{:x}, 0x{:x})",alice_public_key)

    # Bob generates his own key pair.
    bob_private_key, bob_public_key = make_keypair()
    print("Bob's private key:", bob_private_key)
    print("Bob's public key: (0x{:x}, 0x{:x})",bob_public_key)

    # Alice and Bob exchange their public keys and calculate the shared secret.
    s1 = scalar_mult(alice_private_key, bob_public_key)
    s2 = scalar_mult(bob_private_key, alice_public_key)
    assert s1 == s2

    print('Shared secret: (0x{:x}, 0x{:x})',s1)
