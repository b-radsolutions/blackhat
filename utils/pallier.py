import random
from math import gcd, lcm, log2
from utils import prime_handler


def get_extended_factors(a, b):
    if a == 0:
        return 0, 1
    else:
        y, x = get_extended_factors(b % a, a)
        floored_quotient = b // a
        return x - floored_quotient * y, y


def decrypt(c, u, p, q):
    n = p * q
    lamb = lcm(p - 1, q - 1)
    L = lambda x: (x - 1) / n
    return (int(L(pow(c, lamb, n ** 2))) * u) % n


def random_coprime(n):
    while True:
        i = random.randint(2, n)
        if gcd(i, n) == 1:
            return i


def encrypt(n, g, m):
    r = random_coprime(n)
    return (pow(g, m, n ** 2) * pow(r, n, n ** 2)) % (n ** 2)


def increment(c, n, g, m):
    r = random_coprime(n)
    return (c * pow(g, m, n ** 2) * pow(r, n, n ** 2)) % (n ** 2)


def create_config():
    p = next(prime_handler.new24())
    q = next(prime_handler.new24())
    while int(log2(p)) != int(log2(q)):
        q = next(prime_handler.new24())
    n = p * q
    assert gcd(p * q, (p - 1) * (q - 1)) == 1
    # ensure that p and q are equal length primes
    L = lambda x: (x - 1) / n
    lamb = lcm(p - 1, q - 1)
    config = None
    i = 0
    while i < n:
        g = random.randint(1, n ** 2 - 1)
        i += 1
        l = L(pow(g, lamb, n ** 2))
        if l % 1 != 0:
            continue
        l = int(l)
        if gcd(l, n) != 1:
            continue
        u, _ = get_extended_factors(l, n)
        u = u % n
        if u:
            assert (u * l) % n == 1
            config = [p, q, u, g]
            break
    if i == n:
        raise Exception('bad')
    r = random_coprime(n)
    assert gcd(r, n) == 1
    c = pow(r, n, n ** 2)
    config.append(c)
    # format (p, q, u, g, c)
    return config
