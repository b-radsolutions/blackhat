class bitset:
    """
    self.bits is a list of string bits
    """

    def __init__(self, b_str: str):
        self.b_str = b_str

    def __repr__(self):
        return self.b_str

    @staticmethod
    def chunk(string, chunk_size=8):
        return [string[i: min(i + chunk_size, len(string))] for i in range(0, len(string), chunk_size)]

    @classmethod
    def from_str(cls, string: str):
        chars = []
        for char in string:
            _b_str = format(ord(char), 'b')
            # ensure that we are encoding as 8 bit segments
            chars.append("0" * (8 - len(_b_str)) + _b_str)
        return cls("".join(chars))

    def __matmul__(self, other):
        # we will use this operator to represent addition without resizing self
        if type(other) == int:
            other = bitset.from_number(other)
        bit_str = list("0" * len(self.b_str))
        # resize to make equal size if needed
        other_b_str = other.b_str
        if len(other_b_str) < len(self.b_str):
            other_b_str = "0" * (len(self.b_str) - len(other_b_str)) + other_b_str

        other_b_str = other_b_str[-len(self.b_str):]  # take the last x bits
        for i, (b1, b2) in enumerate(zip(reversed(self.b_str), reversed(other_b_str))):
            sum = int(b1) + int(b2) + int(bit_str[i])
            if sum == 0:
                bit_str[i] = '0'
            if sum == 1:
                bit_str[i] = '1'
            if sum == 2:
                bit_str[i] = '0'
                if i + 1 < len(bit_str):
                    bit_str[i + 1] = '1'
            if sum == 3:
                bit_str[i] = '1'
                if i + 1 < len(bit_str):
                    bit_str[i + 1] = '1'
        return bitset("".join(bit_str[::-1]))

    @classmethod
    def from_number(cls, num: int, size=None):
        b_str = format(num, 'b')
        if size:
            if len(b_str) > size:
                return cls(b_str[-size:])
            return cls("0" * (size - len(b_str)) + b_str)
        return cls(format(num, 'b'))

    def to_number(self):
        return int(self.b_str, 2)

    def __lshift__(self, num: int):
        new_bstr = self.b_str + "0" * num
        return bitset(new_bstr)

    def __rshift__(self, other):
        new_bstr = self.b_str[0:-1]
        return bitset(new_bstr)

    def cycle_lshift(self, num):
        assert num >= 0
        num = num%len(self.b_str)
        b_str = self.b_str[num:] + self.b_str[0:num]
        return bitset(b_str)

    def cycle_rshift(self, num):
        assert num >= 0
        num = num % len(self.b_str)
        b_str = self.b_str[-num:] + self.b_str[0:-num]
        return bitset(b_str)

    @staticmethod
    def _marshall_to_bitset(value):
        comp = None
        if type(value) == int:
            comp = bitset.from_number(value)
        if type(value) == bitset:
            comp = value
        if type(value) == str:
            # assume binary string
            comp = bitset(value)
        return comp

    def __xor__(self, other):
        # define general case against another bitset
        # number will be converted to bitset first
        comp = bitset._marshall_to_bitset(other)
        min_len = min(len(self.b_str), len(comp.b_str))
        offset = -1 * max(len(self.b_str) - min_len, len(comp.b_str) - min_len)  # get the difference be
        # figure out which is longer if either
        b_str = ""
        if len(self.b_str) > len(comp.b_str):
            b_str += self.b_str[0:offset]
        elif len(self.b_str) < len(comp.b_str):
            b_str += comp.b_str[0:offset]
        for b1, b2 in zip(self.b_str[-min_len:], comp.b_str[-min_len:]):
            if b1 == b2 and b1 == '1':
                b_str += '0'
            elif b1 == '1' or b2 == '1':
                b_str += '1'
            else:
                b_str += '0'
        return bitset(b_str)

    def __len__(self):
        return len(self.b_str)

    def __add__(self, other):
        """
        :param other: accepts an int, string, or bitset to append
        :return: a new bitset representative of the combination
        """
        other_bset = bitset._marshall_to_bitset(other)
        return bitset(self.b_str + other_bset.b_str)


def test_bitset():
    print('running test set on bitset class')
    t1 = "hello world"
    t1_bitset = bitset.from_str(t1)
    assert len(t1_bitset) % 8 == 0
    # test xor
    xor_test_set = [("0", "1", "1"), ("1", "0", "1"), ("1", "1", "0"), ("0", "0", "0")]
    for b1, b2, s in xor_test_set:
        assert (bitset(b1) ^ bitset(b2)).__repr__() == s
    # test shifts
    lshift_test_set = [("1", 5, "100000"), ("1", 0, "1")]
    for b1, num, s in lshift_test_set:
        assert (bitset(b1) << num).__repr__() == s

    rshift_test_set = [("1", 1, ""), ("10", 1, "1")]
    for b1, num, s in rshift_test_set:
        assert (bitset(b1) >> num).__repr__() == s

    # test add
    add_test_set = [("1", "1", "0"), ("10", "1", "11"), ("1", "10", "1"), ("0", "0", "0"), ("111", "1", "000")]
    for b1, b2, s in add_test_set:
        bitset_1 = bitset(b1)
        bitset_2 = bitset(b2)
        comb = bitset_1 @ bitset_2
        assert (comb).__repr__() == s

    # test to number
    to_num_test_set = [("00001", 1), ("10", 2)]
    for b, s in to_num_test_set:
        assert bitset(b).to_number() == s
