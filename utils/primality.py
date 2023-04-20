import secrets
import math

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

"""
def gcd(a, b):
    r = a % b
    while r:
        a = b
        b = r
        r = a % b
    return b
"""
gcd = math.gcd

"""
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
"""
def primality_test(num: int, k=None) -> bool:
    """
    Tests the primality of `num`. This tests trivial cases, then uses the Miller-Rabin primality test with `k` iterations.

    Parameters
    ----
       - `num` - the number to check the primality of.
       - `k` - the number of iterations of Miller-Rabin primality test to use. If `None` (default), k=8log_2(num)

    Returns
    ----
    `False` if the `num` is found to be composite, or `True` if it was not.
    The probability of a composite number being found to be prime is, worst case, (1/4)^k
    """
    # Invalid integers
    if not isinstance(num, int) or num <= 1:
        return False
    # Divide by low factors
    LOWEST_200_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 292, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
                         127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
                         257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
                         401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
                         563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
                         709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
                         877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031,
                         1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171,
                         1181, 1187, 1193, 1201, 1213, 1217, 1223]
    if num in LOWEST_200_PRIMES:
        return True
    if any([num % x == 0 for x in LOWEST_200_PRIMES]):
        return False
    # Then do Miller-Rabin if we don't have an easy answer
    if k is None:
        k = int(math.log2(num)) * 8
    d = num - 1
    s = 0

    while d & 1 == 0 and d != 0:
        assert (d // 2) * 2 == d
        d = d // 2
        s += 1
    assert d * (2 ** s) == num - 1
    for _ in range(k):
        a = secrets.randbelow(num - 4) + 2
        x = pow(a, d, num)
        for _ in range(s):
            y = pow(x, 2, num)
            if y == 1 and x != 1 and x != num - 1:
                return False
            x = y
        if x != 1:
            return False
    return True

check = lambda x: primality_test(x, 128)

# do not instantiate this more than once, use the singleton in utils.__init__
class PrimeHandler:
    def __init__(self):
        self.non_primes = set()
        self.generator = self._new()
        #self.gen32 = self._new(32)
        self.gen24 = self._new(24)
        #self.gen16 = self._new(16)

    #def new16(self):
    #    return self.gen16

    def new24(self):
        return self.gen24

    #def new32(self):
    #    return self.gen32

    def new(self):
        return self.generator
    
    def _new(self, b=64):
        while True:
            p = secrets.randbits(b)
            if p not in self.non_primes and check(p):
                yield p

    """
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
    """