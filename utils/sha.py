import math

# passing the file name and path as argument
import sys

sys.path.append("..")
from models.bitset import bitset

def _sha1(message: str, convert:bool = True):
    """
    :param message: a string message to be hashed
    :return: 5 32 bit blocks representing the 5 blocks propagated through sha1
    """
    # convert the string to an array of bits
    if convert:
        mbits = bitset.from_str(message)
    else:
        mbits = message
    # constants designed for sha

    h_1 = 0x67452301
    h_2 = 0xEFCDAB89
    h_3 = 0x98BADCFE
    h_4 = 0x10325476
    h_5 = 0xC3D2E1F0

    # format into a multiple of 512 bits
    bits = mbits + "1"
    # need to tack on bits to make this strictly 512*r-64 bits
    diff_512 = ((math.ceil(len(bits) / 512) * 512) - len(bits))  # will give the bits to the nearest 512
    assert (diff_512 + len(bits)) % 512 == 0
    if diff_512 >= 64:
        zeros = "0" * (diff_512 - 64)
    else:
        zeros = "0" * (448 + diff_512)
    bits = bits + zeros
    mlen = bitset.from_number(len(mbits))
    mlen = bitset("0" * (64 - len(mlen)) + mlen.__repr__())  # prepend with 0's to make a 64 bit string
    assert len(bits) % 512 == 448
    assert len(mlen) == 64
    bits = bits + mlen
    assert len(bits) % 512 == 0

    # chunk into segments of 512 bits
    chunks: [str] = bitset.chunk(bits.__repr__(), 512)
    for chunk in chunks:
        words = [bitset(b_str) for b_str in bitset.chunk(chunk, 32)] + [0] * 64
        for i in range(16, 80):
            words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).cycle_lshift(1)

        # setup our initial hash values
        a = h_1
        b = h_2
        c = h_3
        d = h_4
        e = h_5

        for i in range(80):
            # a, b, c, d, and e should all be numbers at this point
            if 0 <= i <= 19:
                f = (b & c) ^ (~b & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) ^ (b & d) ^ (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            # ensure that we have 32 bit chunks
            a, b, c, d, e, f, k = bitset.from_number(a, 32), bitset.from_number(b, 32), bitset.from_number(c, 32), \
                                  bitset.from_number(d, 32), bitset.from_number(e, 32), bitset.from_number(f, 32), \
                                  bitset.from_number(k, 32)
            temp = (a.cycle_lshift(5)) @ f @ e @ k @ words[i]
            e = d
            d = c
            c = (b.cycle_lshift(30))
            b = a
            a = temp
            a, b, c, d, e, f, k = bitset.to_number(a), bitset.to_number(b), bitset.to_number(c), bitset.to_number(
                d), bitset.to_number(e), bitset.to_number(f), bitset.to_number(k)

        h_1 = (bitset.from_number(h_1, 32) @ bitset.from_number(a)).to_number()
        h_2 = (bitset.from_number(h_2, 32) @ bitset.from_number(b)).to_number()
        h_3 = (bitset.from_number(h_3, 32) @ bitset.from_number(c)).to_number()
        h_4 = (bitset.from_number(h_4, 32) @ bitset.from_number(d)).to_number()
        h_5 = (bitset.from_number(h_5, 32) @ bitset.from_number(e)).to_number()
    return h_1, h_2, h_3, h_4, h_5


def hash(message: str):
    """
    :param message: A string to hash
    :return: a 160 bit representative of the hash of the string
    """
    h_1, h_2, h_3, h_4, h_5 = _sha1(message)

    return h_1 << 128 | h_2 << 96 | h_3 << 64 | h_4 << 32 | h_5
def hashNC(message: str):
    """
    :param message: A string to hash
    :return: a 160 bit representative of the hash of the string
    """
    h_1, h_2, h_3, h_4, h_5 = _sha1(message, False)
    return h_1 << 128 | h_2 << 96 | h_3 << 64 | h_4 << 32 | h_5

def hashNC(message: str):
    """
    :param message: A string to hash
    :return: a 160 bit representative of the hash of the string
    """
    h_1, h_2, h_3, h_4, h_5 = _sha1(message, False)
    return h_1 << 128 | h_2 << 96 | h_3 << 64 | h_4 << 32 | h_5


def hex(message: str):
    """
    :param message: string message to hash
    :return: a hex string representative of the hash but in hex
    this is mostly used for validation as it significantly reduces the length of the hash
    """
    return '%08x%08x%08x%08x%08x' % _sha1(message, False)
