import re

import pytest

from umbral.serializable import Serializable, bool_bytes, bool_from_exact_bytes


class A(Serializable):

    def __init__(self, val: int):
        assert 0 <= val < 2**32
        self.val = val

    @classmethod
    def serialized_size(cls):
        return 4

    @classmethod
    def _from_exact_bytes(cls, data):
        return cls(int.from_bytes(data, byteorder='big'))

    def __bytes__(self):
        return self.val.to_bytes(self.serialized_size(), byteorder='big')

    def __eq__(self, other):
        return isinstance(other, A) and self.val == other.val


class B(Serializable):

    def __init__(self, val: int):
        assert 0 <= val < 2**16
        self.val = val

    @classmethod
    def serialized_size(cls):
        return 2

    @classmethod
    def _from_exact_bytes(cls, data):
        return cls(int.from_bytes(data, byteorder='big'))

    def __bytes__(self):
        return self.val.to_bytes(self.serialized_size(), byteorder='big')

    def __eq__(self, other):
        return isinstance(other, B) and self.val == other.val


class C(Serializable):

    def __init__(self, a: A, b: B):
        self.a = a
        self.b = b

    @classmethod
    def serialized_size(cls):
        return A.serialized_size() + B.serialized_size()

    @classmethod
    def _from_exact_bytes(cls, data):
        components = cls._split(data, A, B)
        return cls(*components)

    def __bytes__(self):
        return bytes(self.a) + bytes(self.b)

    def __eq__(self, other):
        return isinstance(other, C) and self.a == other.a and self.b == other.b


def test_normal_operation():
    a = A(2**32 - 123)
    b = B(2**16 - 456)
    c = C(a, b)
    c_back = C.from_bytes(bytes(c))
    assert c_back == c


def test_too_many_bytes():
    a = A(2**32 - 123)
    b = B(2**16 - 456)
    c = C(a, b)
    with pytest.raises(ValueError, match="Expected 6 bytes, got 7"):
        C.from_bytes(bytes(c) + b'\x00')


def test_not_enough_bytes():
    a = A(2**32 - 123)
    b = B(2**16 - 456)
    c = C(a, b)
    # Will happen on deserialization of B - 1 byte missing
    with pytest.raises(ValueError, match="Expected 6 bytes, got 5"):
        C.from_bytes(bytes(c)[:-1])


def test_bool_bytes():
    assert bool_from_exact_bytes(bool_bytes(True)) == True
    assert bool_from_exact_bytes(bool_bytes(False)) == False
    error_msg = re.escape("Incorrectly serialized boolean; expected b'\\x00' or b'\\x01', got b'z'")
    with pytest.raises(ValueError, match=error_msg):
        bool_from_exact_bytes(b'z')


def test_split_bool():
    a = A(2**32 - 123)
    b = True
    data = bytes(a) + bool_bytes(b)
    a_back, b_back = Serializable._split(data, A, bool)
    assert a_back == a
    assert b_back == b
