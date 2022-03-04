import random
import sys

def ipow(a, b, n):
    """calculates (a**b) % n via binary exponentiation, yielding itermediate
       results as Rabin-Miller requires"""
    A = a = int(a % n)
    yield A
    t = 1
    while t <= b:
        t <<= 1

    # t = 2**k, and t > b
    t >>= 2
    
    while t:
        A = (A * A) % n
        if t & b:
            A = (A * a) % n
        yield A
        t >>= 1

# Pre-declared primes under 100 to alleviate processing at 'likely_prime()'
primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
            31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
                73, 79, 83, 89, 97)

# Binary exponentiation function to calculate (a ** b) % n
def miller_test(a, b, n):
    A = a = int(a % n)
    yield A
    t = 1
    while t <= b:
        t <<= 1
    t >>= 2
    
    while t:
        A = (A * A) % n
        if t & b:
            A = (A * a) % n
        yield A

# Primality test function performed for each 'k' trial.
# returns True if composite number
# returns False if possibily a prime number
def rabin_miller_primality(test, possible):
    return 1 not in ipow(test, possible-1, possible)

def default_k(bits):
    # Minimum number of millier_test held (k) = 50
    return int(max(40, 2 * bits))

# returns True if possibily a prime number
# returns False if composite number
def likely_prime(possible, k = None):
    if possible == 1:
        return True
    if k is None:
        k = default_k(possible.bit_length())
    for i in primes:
        if possible == i:
            return True
        if possible % i == 0:
            return False
    for i in range(k):
        test = random.randrange(2, possible - 1) | 1
        if rabin_miller_primality(test, possible) == True:
            return False
    return True

def generate_prime(bits, k = None):  
    assert bits >= 8
    if k is None:
        k = default_k(bits)

    while True:
        possible = random.randrange(2 ** (bits-1) + 1, 2 ** bits) | 1
        if likely_prime(possible, k):
           return possible