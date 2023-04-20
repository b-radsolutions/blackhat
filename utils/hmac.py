import utils.sha as sha
# import sys
# sys.path.append("..")
# passing the file name and path as argument
from models.bitset import bitset


def GenerateHMAC(message: str, key: str):
    m_bits = bitset.from_str(message)
    b = 512
    if type(key) == str:
        k_bits = bitset.from_str(key)
    elif type(key) == bitset:
        k_bits = key
    elif type(key) == int:
        k_bits = bitset.from_number(key)

    # Generate K_prime at the bit size
    if (len(k_bits.b_str) > b):
        k_bits = bitset.from_number(sha.hash(key))
    elif (len(k_bits.b_str) < b):
        k_bits = bitset("0" * (b - len(k_bits.b_str)) + k_bits.b_str)

    o = "0" + bitset.from_number(0x5c).b_str
    i = "00" + bitset.from_number(0x36).b_str
    o_key_pad = "".join([o for n in range(b // 8)])
    i_key_pad = "".join([i for n in range(b // 8)])

    o_key_pad = bitset(o_key_pad) ^ k_bits
    i_key_pad = bitset(i_key_pad) ^ k_bits

    inner = sha.hashNC(i_key_pad.__add__(m_bits))
    first_hash = bitset.from_number(inner)
    second_hash = sha.hex(o_key_pad.__add__(first_hash))
    return second_hash


def ValidateHMAC(message: str, key: str, HMAC: str):
    test = GenerateHMAC(message, key)
    return (HMAC == test)
