import secrets
import random
from multiprocessing import Pool, cpu_count


def eeulers(a, b):
    if a == 0:
        return 0, 1
    else:
        y, x = eeulers(b % a, a)
        floored_quotient = b // a
        return x - floored_quotient * y, y


def order(a, n, l=1):
    # finds the order of a
    for i in range(l, n):
        if pow(a, i, n) == 1:
            return i


def gcd(a, b):
    r = a % b
    while r:
        a = b
        b = r
        r = a % b
    return b


# determines is prime
def check(n: int):
    # implements miller-rabin with k rounds
    k = 128
    if n % 2 == 0:
        return False
    # generate s and d
    false_payload = False, n
    true_payload = True, n
    d = n - 1
    s = 0
    while d % 2 == 0:
        d = d / 2
        s += 1
    d = int(d)
    for i in range(0, k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        for i in range(0, s):
            y = pow(x, 2, n)
            if y == 1 and x != 1 and x != n - 1:
                return false_payload
            x = y
        if y != 1:
            return false_payload
    return true_payload


# do not instantiate this more than once, use the singleton in utils.__init__
class PrimeHandler:
    def __init__(self):
        self.non_primes = set()
        self.generator = self._new()
        self.gen32 = self._new(32)
        self.gen24 = self._new(24)
        self.gen16 = self._new(16)

    def new16(self):
        return self.gen16

    def new24(self):
        return self.gen24

    def new32(self):
        return self.gen32

    def new(self):
        return self.generator

    def _new(self, b=64):
        rand = lambda: secrets.randbits(b)
        p = rand()  # generates a 1024 bit prime
        tested = set()
        chunk_size = 100
        with Pool(cpu_count() - 1) as pool:
            while True:
                for i in range((cpu_count() - 1) * chunk_size):
                    p_list = set()
                    while p in self.non_primes or p % 2 == 0 or p in p_list or p in tested:
                        p = rand()
                    p_list.add(p)
                for result in pool.imap(check, p_list, chunk_size):
                    is_prime, n = result
                    tested.add(n)
                    if is_prime:
                        yield n
                    else:
                        self.non_primes.add(n)
