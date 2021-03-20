import pytest

from umbral.curve import CURVE
from umbral.curve_scalar import CurveScalar
from umbral.hashing import Hash


def test_random():
    r1 = CurveScalar.random_nonzero()
    r2 = CurveScalar.random_nonzero()
    assert r1 != r2
    assert not r1.is_zero()
    assert not r2.is_zero()


def test_from_and_to_int():
    zero = CurveScalar.from_int(0)
    assert zero.is_zero()
    assert int(zero) == 0

    one = CurveScalar.one()
    assert not one.is_zero()
    assert int(one) == 1

    big_int = CURVE.order - 2
    big_scalar = CurveScalar.from_int(big_int)
    assert int(big_scalar) == big_int

    # normalization check
    with pytest.raises(ValueError):
        CurveScalar.from_int(CURVE.order)

    # disable normalization check
    too_big = CurveScalar.from_int(CURVE.order, check_normalization=False)


def test_from_digest():
    digest = Hash(b'asdf')
    digest.update(b'some info')
    s1 = CurveScalar.from_digest(digest)

    digest = Hash(b'asdf')
    digest.update(b'some info')
    s2 = CurveScalar.from_digest(digest)

    assert s1 == s2
    assert int(s1) == int(s2)


def test_eq():
    random = CurveScalar.random_nonzero()
    same = CurveScalar.from_int(int(random))
    different = CurveScalar.random_nonzero()
    assert random == same
    assert random == int(same)
    assert random != different
    assert random != int(different)


def test_serialization_rotations_of_1():

    size_in_bytes = CURVE.scalar_size
    for i in range(size_in_bytes):
        lonely_one = 1 << i
        bn = CurveScalar.from_int(lonely_one)
        lonely_one_in_bytes = lonely_one.to_bytes(size_in_bytes, 'big')

        # Check serialization
        assert bytes(bn) == lonely_one_in_bytes

        # Check deserialization
        assert CurveScalar.from_bytes(lonely_one_in_bytes) == bn


def test_invalid_deserialization():
    size_in_bytes = CURVE.scalar_size

    # All-ones bytestring is invalid (since it's greater than the order)
    lots_of_ones = b'\xFF' * size_in_bytes
    with pytest.raises(ValueError):
        CurveScalar.from_bytes(lots_of_ones)

    # Serialization of `order` is invalid since it's not strictly lower than
    # the order of the curve
    order = CURVE.order
    with pytest.raises(ValueError):
        CurveScalar.from_bytes(order.to_bytes(size_in_bytes, 'big'))

    # On the other hand, serialization of `order - 1` is valid
    order -= 1
    CurveScalar.from_bytes(order.to_bytes(size_in_bytes, 'big'))


def test_add():
    r1 = CurveScalar.random_nonzero()
    r2 = CurveScalar.random_nonzero()
    r1i = int(r1)
    r2i = int(r2)
    assert r1 + r2 == (r1i + r2i) % CURVE.order
    assert r1 + r2i == (r1i + r2i) % CURVE.order


def test_sub():
    r1 = CurveScalar.random_nonzero()
    r2 = CurveScalar.random_nonzero()
    r1i = int(r1)
    r2i = int(r2)
    assert r1 - r2 == (r1i - r2i) % CURVE.order
    assert r1 - r2i == (r1i - r2i) % CURVE.order


def test_mul():
    r1 = CurveScalar.random_nonzero()
    r2 = CurveScalar.random_nonzero()
    r1i = int(r1)
    r2i = int(r2)
    assert r1 * r2 == (r1i * r2i) % CURVE.order
    assert r1 * r2i == (r1i * r2i) % CURVE.order


def test_invert():
    r1 = CurveScalar.random_nonzero()
    r1i = int(r1)
    r1inv = r1.invert()
    assert r1 * r1inv == CurveScalar.one()
    assert (r1i * int(r1inv)) % CURVE.order == 1

