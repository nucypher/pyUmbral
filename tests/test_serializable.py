import re

import pytest

from umbral.serializable import Serializable, serialize_bool, take_bool


class A(Serializable):

    def __init__(self, val: int):
        assert 0 <= val < 2**32
        self.val = val

    @classmethod
    def __take__(cls, data):
        val_bytes, data = cls.__take_bytes__(data, 4)
        return cls(int.from_bytes(val_bytes, byteorder='big')), data

    def __bytes__(self):
        return self.val.to_bytes(4, byteorder='big')

    def __eq__(self, other):
        return isinstance(other, A) and self.val == other.val


class B(Serializable):

    def __init__(self, val: int):
        assert 0 <= val < 2**16
        self.val = val

    @classmethod
    def __take__(cls, data):
        val_bytes, data = cls.__take_bytes__(data, 2)
        return cls(int.from_bytes(val_bytes, byteorder='big')), data

    def __bytes__(self):
        return self.val.to_bytes(2, byteorder='big')

    def __eq__(self, other):
        return isinstance(other, B) and self.val == other.val


class C(Serializable):

    def __init__(self, a: A, b: B):
        self.a = a
        self.b = b

    @classmethod
    def __take__(cls, data):
        components, data = cls.__take_types__(data, A, B)
        return cls(*components), data

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
    with pytest.raises(ValueError, match="1 bytes remaining after deserializing"):
        C.from_bytes(bytes(c) + b'\x00')


def test_not_enough_bytes():
    a = A(2**32 - 123)
    b = B(2**16 - 456)
    c = C(a, b)
    # Will happen on deserialization of B - 1 byte missing
    with pytest.raises(ValueError, match="cannot take 2 bytes from a bytestring of size 1"):
        C.from_bytes(bytes(c)[:-1])


def test_serialize_bool():
    assert take_bool(serialize_bool(True) + b'1234') == (True, b'1234')
    assert take_bool(serialize_bool(False) + b'12') == (False, b'12')
    error_msg = re.escape("Incorrectly serialized boolean; expected b'\\x00' or b'\\x01', got b'z'")
    with pytest.raises(ValueError, match=error_msg):
        take_bool(b'z1234')
