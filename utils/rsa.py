import secrets
from utils.sha import hashNC
from models.bitset import bitset
from utils.primality import gcd, eeulers
from utils import prime_handler
import random


def keys():
    # generates a new set of keys, p, q, e, d
    generator = prime_handler.new()
    p = next(generator)
    q = next(generator)
    N = p * q
    totient = (p - 1) * (q - 1)
    e = random.randint(2, totient)
    while gcd(e, totient) != 1:
        e = random.randint(2, totient)
    d, _ = eeulers(e, totient)
    assert (d * e) % totient == 1
    return N, p, q, e, d


def encrypt(e, N, m):
    # DO NOT ENCODE A MESSAGE LONGER THAN 128 BITS
    assert len(format(m, 'b')) <= 128
    k = len(format(N, 'b'))
    r = secrets.randbits(k - 1)
    H_r = hashNC(bitset.from_number(r))
    return rsa_encrypt(e, N, r), m ^ H_r


def decrypt(d, N, c):
    y1, y2 = c
    r = rsa_decrypt(d, N, y1)
    return y2 ^ hashNC(bitset.from_number(r))


def rsa_encrypt(e, N, m):
    return pow(m, e, N)


def rsa_decrypt(d, N, c):
    return pow(c, d, N)
