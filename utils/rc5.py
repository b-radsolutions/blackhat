from models.bitset import bitset
from math import e, sqrt, ceil
import struct

golden = (1.0 + sqrt(5)) / 2.0


def convert_to_unsigned(i, w=16):
    if i > 0:
        # no need to convert
        return i
    lookup = {
        1: ('b', 'B'),
        2: ('h', 'H'),
        4: ('i', 'I'),
        8: ('q', 'Q')
    }
    key = lookup[8]
    return struct.unpack_from(key[1], struct.pack(key[0], i))[0]


#
def keys(key: bitset, w=16, b=16, r=20):
    # b*8 bits in key, b bytes
    assert len(key) == b * 8
    assert w % 8 == 0
    key_chunks = bitset.chunk(key.__repr__(), 8)  # partition into bytes
    assert len(key_chunks) == b
    u = int(w / 8)  # word size in bytes
    _P = (e - 2) * pow(2, w)
    # use remainder to determine which way to go
    odd = lambda x: int(x + (1 - x % 2))
    P = bitset.from_number(odd((e - 2) * pow(2, w)), w).to_number()
    Q = bitset.from_number(odd((golden - 1) * pow(2, w)), w).to_number()
    if w == 16:
        assert P == 0xB7E1  # for w=16
        assert Q == 0x9E37  # for w=16
    if w == 32:
        assert P == 0xB7E15163
        assert Q == 0x9E3779B9
    c = ceil(max(b, 1) / u)
    L: [int] = [0 for _ in range(0, c)]
    for i in range(b - 1, -1, -1):
        L[i // u] = bitset.from_number(L[i // u] << 8 + bitset(key_chunks[i]).to_number(), w).to_number()
    t = 2 * (r + 1)
    S: [int] = [0 for _ in range(0, t)]
    S[0] = P
    for i in range(1, t):
        S[i] = bitset.from_number(S[i - 1] + Q, w).to_number()
    i = j = 0
    A = B = 0

    for _ in range(0, 3 * max(t, c)):
        A = S[i] = bitset.from_number(S[i] + A + B, w).cycle_lshift(3).to_number()
        B = L[j] = bitset.from_number(L[j] + A + B, w).cycle_lshift(
            A + B).to_number()
        i = (i + 1) % t
        j = (j + 1) % c
    return S


# implementing rc5
def encrypt_words(A, B, S, r=20, w=16):
    A = bitset.from_number(A + S[0], w).to_number()
    B = bitset.from_number(B + S[1], w).to_number()

    for i in range(1, r + 1):
        A = bitset.from_number(bitset.from_number(A ^ B, w).cycle_lshift(B).to_number() + S[2 * i], w).to_number()
        B = bitset.from_number(bitset.from_number(A ^ B, w).cycle_lshift(A).to_number() + S[2 * i + 1], w).to_number()
    # format A and B into w bit strings
    return bitset.from_number(A, w).__repr__(), bitset.from_number(B, w).__repr__()


def encrypt(key: bitset, message, r=20, w=16, _type=str):
    # message can be either a bitset or
    assert len(key.__repr__()) % 8 == 0
    b = len(key.__repr__()) // 8  # convert to bytes
    m_bits = message
    if type(message) == str:
        m_bits = bitset.from_str(message)
    assert len(m_bits) % 8 == 0  # encode each char as a 1 byte
    if len(m_bits) % (w * 2) != 0:
        chars = (w * 2) - len(m_bits) % (w * 2)
        assert chars % 8 == 0
        chars = chars // 8
        m_bits = m_bits + bitset.from_str('\0' * chars)
    words = [bitset(_).to_number() for _ in bitset.chunk(m_bits.__repr__(), w)]
    assert len(words) % 2 == 0
    S = keys(key, r=r, w=w, b=b)
    # encrypt message words
    encrypted_words = []
    word_iter = iter(words)

    for A, B in zip(word_iter, word_iter):
        A, B = encrypt_words(A, B, S, r=r, w=w)
        encrypted_words.extend([A, B])
    if _type == str:
        return "".join([str(i) for i in encrypted_words])
    return encrypted_words


def decrypt_ciphers(A, B, S, r=20, w=16):
    for i in range(r, 0, -1):
        _b = convert_to_unsigned(B - S[2 * i + 1], w)
        B = bitset.from_number(convert_to_unsigned(B - S[2 * i + 1], w), w).cycle_rshift(A).to_number() ^ A
        _a = convert_to_unsigned(A - S[2 * i], w)
        A = (bitset.from_number(convert_to_unsigned(A - S[2 * i], w), w).cycle_rshift(B).to_number()) ^ B
    B = convert_to_unsigned(B - S[1], w)
    A = convert_to_unsigned(A - S[0], w)
    return A, B


def decrypt(key: bitset, cipher: str, r=20, w=16, _type=str):
    ciphers = [int(cipher[i: min(i + w, len(cipher))], 2) for i in range(0, len(cipher), w)]
    assert len(key.__repr__()) % 8 == 0
    b = len(key.__repr__()) // 8  # convert to bytes
    S = keys(key, r=r, w=w, b=b)
    cipher_iter = iter(ciphers)
    decrypted_ciphers = []
    for A, B in zip(cipher_iter, cipher_iter):
        A, B = decrypt_ciphers(A, B, S, r=r, w=w)
        decrypted_ciphers.extend([A, B])
    if not _type:
        return decrypted_ciphers
    if _type == str:
        return "".join(
            ["".join([str(chr(int(a, 2))) for a in bitset.chunk(bitset.from_number(d, w).__repr__(), 8)]) for d in
             decrypted_ciphers]).replace('\0', '')
