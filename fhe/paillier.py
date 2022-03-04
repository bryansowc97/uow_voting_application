import math
import libnum
from fhe import bit_primes

class Public_Key(object):

    @classmethod
    def from_n(cls, n):
        return cls(n)

    def __init__(self, n):
        self.n = n
        self.n_sq = n * n
        self.g = n + 1      # As we are using bit-controlled lengths equivilent for 'p' & 'q'

    def __repr__(self):
        return '<Public Key: (n: %s, g: %s)>' % (self.n, self.g)

class PrivateKey(object):

    def __init__(self, p, q, n):
        self.gLambda = (p-1) * (q-1)
        self.gMu = libnum.invmod(self.gLambda, n)

    def __repr__(self):
        return '<PrivateKey: (Lambda: %s, Mu: %s)>' % (self.gLambda, self.gMu)

def notObjectPublicKey(n):
    return n

def notObjectPrivateKey(p, q, n):
    l = (p-1) * (q-1)
    m = libnum.invmod(l, n)
    return l, m

def generate_keypair(bits):
    p = bit_primes.generate_prime(bits / 2)
    q = bit_primes.generate_prime(bits / 2)
    n = p * q

    return notObjectPrivateKey(p, q, n), notObjectPublicKey(n)

def encrypt(pub, message):
    while True:
        r = bit_primes.generate_prime(int(round(math.log(pub, 2))))
        if r > 0 and r < pub:
            break

    pub_sq = pub * pub
    pub_g = pub + 1

    x = pow(r, pub, pub_sq)
    cipher = (pow(pub_g, message, pub_sq) * x) % pub_sq
    return cipher

def sum_cipher(pub, a, b):
    """Add one encrypted integer to another"""
    pub_sq = pub * pub
    return a * b % pub_sq

def decrypt(priv_l, priv_m, pub, cipher):
    pub_sq = pub * pub
    x = pow(cipher, priv_l, pub_sq) - 1
    message = ((x // pub) * priv_m) % pub
    return message

'''
def generate_keypair(bits):
    p = bit_primes.generate_prime(bits/2) 
    q = bit_primes.generate_prime(bits/2)
    n = p * q
    return Public_Key(n), PrivateKey(p, q, n)

def sum_cipher(public_key, a, b):
    return a * b % public_key.n_sq

def encrypt(public_key, message):
    while True:
        r = bit_primes.generate_prime(int(round(math.log(public_key.n, 2))))
        if r > 0 and r < public_key.n:
            break
    x = pow(r, public_key.n, public_key.n_sq)
    cipher = (pow(public_key.g, message, public_key.n_sq) * x) % public_key.n_sq
    return cipher

def decrypt(private_key, public_key, cipher):
    x = pow(cipher, private_key.gLambda, public_key.n_sq) - 1
    message = ((x // public_key.n) * private_key.gMu) % public_key.n
    return message
'''