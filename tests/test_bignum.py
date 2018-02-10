from umbral.bignum import BigNum


def test_mocked_openssl_bignum_arithmetic(mock_openssl, random_ec_bignum1, random_ec_bignum2):
    with mock_openssl():
        _ = random_ec_bignum1 == random_ec_bignum1     # __eq__
        _ = random_ec_bignum1 * random_ec_bignum2      # __mul__
        _ = random_ec_bignum1 ** random_ec_bignum2     # __pow__
        _ = random_ec_bignum1 + random_ec_bignum2      # __add__
        _ = random_ec_bignum1 - random_ec_bignum2      # __sub__
        _ = random_ec_bignum1 % random_ec_bignum2      # __mod__
        _ = ~random_ec_bignum1                         # __invert__


def test_cast_bignum_to_int():
    x = BigNum.gen_rand()

    x_as_int_from_dunder = x.__int__()
    x_as_int_type_caster = int(x)
    assert x_as_int_from_dunder == x_as_int_type_caster
    x = x_as_int_type_caster

    y = BigNum.from_int(x)
    assert x == y


def test_bn_to_cryptography_privkey():
    bn = BigNum.gen_rand()
    crypto_privkey = bn.to_cryptography_priv_key()
    assert int(bn) == crypto_privkey.private_numbers().private_value

