import json
import os

from umbral import (
    Capsule, KeyFrag, CapsuleFrag, SecretKey, PublicKey, encrypt, generate_kfrags, reencrypt)
from umbral.curve_scalar import CurveScalar
from umbral.curve_point import  CurvePoint
from umbral.hashing import Hash, unsafe_hash_to_point
from umbral.dem import DEM, kdf


def test_scalar_operations():

    vector_file = os.path.join('vectors', 'vectors_scalar_operations.json')
    try:
        with open(vector_file) as f:
            vector_suite = json.load(f)
    except OSError:
        raise

    bn1 = CurveScalar.from_bytes(bytes.fromhex(vector_suite['first operand']))
    bn2 = CurveScalar.from_bytes(bytes.fromhex(vector_suite['second operand']))

    expected = dict()
    for op_result in vector_suite['vectors']:
        result = bytes.fromhex(op_result['result'])
        expected[op_result['operation']] = CurveScalar.from_bytes(result)

    test = [('Addition', bn1 + bn2),
            ('Subtraction', bn1 - bn2),
            ('Multiplication', bn1 * bn2),
            ('Inverse', bn1.invert()),
            ]

    for (operation, result) in test:
        assert result == expected[operation], 'Error in {}'.format(operation)

def test_scalar_hash():

    vector_file = os.path.join('vectors', 'vectors_scalar_from_digest.json')
    try:
        with open(vector_file) as f:
            vector_suite = json.load(f)
    except OSError:
        raise

    for vector in vector_suite['vectors']:
        hash_input = [bytes.fromhex(item['bytes']) for item in vector['input']]
        expected = CurveScalar.from_bytes(bytes.fromhex(vector['output']))

        digest = Hash(b'some_dst')
        for input_ in hash_input:
            digest.update(input_)
        scalar = CurveScalar.from_digest(digest)
        assert scalar == expected


def test_point_operations():

    vector_file = os.path.join('vectors', 'vectors_point_operations.json')
    try:
        with open(vector_file) as f:
            vector_suite = json.load(f)
    except OSError:
        raise

    point1 = CurvePoint.from_bytes(bytes.fromhex(vector_suite['first CurvePoint operand']))
    point2 = CurvePoint.from_bytes(bytes.fromhex(vector_suite['second CurvePoint operand']))
    bn1 = CurveScalar.from_bytes(bytes.fromhex(vector_suite['CurveScalar operand']))

    expected = dict()
    for op_result in vector_suite['vectors']:
        expected[op_result['operation']] = bytes.fromhex(op_result['result'])

    test = [('Addition', point1 + point2),
            ('Subtraction', point1 - point2),
            ('Multiplication', point1 * bn1),
            ('Inversion', -point1),
            ]

    for (operation, result) in test:
        assert result == CurvePoint.from_bytes(expected[operation]), 'Error in {}'.format(operation)

    test = [('To_affine.X', point1.to_affine()[0]),
            ('To_affine.Y', point1.to_affine()[1]),
            ]

    for (operation, result) in test:
        assert result == int.from_bytes(expected[operation], 'big'), 'Error in {}'.format(operation)

    assert kdf(bytes(point1), DEM.KEY_SIZE) == expected['kdf']


def test_unsafe_hash_to_point():

    vector_file = os.path.join('vectors', 'vectors_unsafe_hash_to_point.json')
    try:
        with open(vector_file) as f:
            vector_suite = json.load(f)
    except OSError:
        raise

    for item in vector_suite['vectors']:
        data = bytes.fromhex(item['data'])
        dst = bytes.fromhex(item['dst'])
        expected = CurvePoint.from_bytes(bytes.fromhex(item['point']))
        assert expected == unsafe_hash_to_point(dst=dst, data=data)


def test_kfrags():

    vector_file = os.path.join('vectors', 'vectors_kfrags.json')
    try:
        with open(vector_file) as f:
            vector_suite = json.load(f)
    except OSError:
        raise

    verifying_pk = PublicKey.from_bytes(bytes.fromhex(vector_suite['verifying_pk']))
    delegating_pk = PublicKey.from_bytes(bytes.fromhex(vector_suite['delegating_pk']))
    receiving_pk = PublicKey.from_bytes(bytes.fromhex(vector_suite['receiving_pk']))

    for json_kfrag in vector_suite['vectors']:
        kfrag = KeyFrag.from_bytes(bytes.fromhex(json_kfrag['kfrag']))
        assert kfrag.verify(signing_pk=verifying_pk,
                            delegating_pk=delegating_pk,
                            receiving_pk=receiving_pk), \
            'Invalid KeyFrag {}'.format(bytes(kfrag).hex())


def test_cfrags():

    vector_file = os.path.join('vectors', 'vectors_cfrags.json')
    try:
        with open(vector_file) as f:
            vector_suite = json.load(f)
    except OSError:
        raise

    capsule = Capsule.from_bytes(bytes.fromhex(vector_suite['capsule']))

    verifying_pk = PublicKey.from_bytes(bytes.fromhex(vector_suite['verifying_pk']))
    delegating_pk = PublicKey.from_bytes(bytes.fromhex(vector_suite['delegating_pk']))
    receiving_pk = PublicKey.from_bytes(bytes.fromhex(vector_suite['receiving_pk']))

    kfrags_n_cfrags = [(KeyFrag.from_bytes(bytes.fromhex(json_kfrag['kfrag'])),
                        CapsuleFrag.from_bytes(bytes.fromhex(json_kfrag['cfrag'])))
                       for json_kfrag in vector_suite['vectors']]

    metadata = bytes.fromhex(vector_suite['metadata'])

    for kfrag, cfrag in kfrags_n_cfrags:
        assert kfrag.verify(signing_pk=verifying_pk,
                            delegating_pk=delegating_pk,
                            receiving_pk=receiving_pk), \
            'Invalid KeyFrag {}'.format(bytes(kfrag.to_bytes).hex())

        new_cfrag = reencrypt(capsule, kfrag, metadata=metadata)
        assert new_cfrag.point_e1 == cfrag.point_e1
        assert new_cfrag.point_v1 == cfrag.point_v1
        assert new_cfrag.kfrag_id == cfrag.kfrag_id
        assert new_cfrag.precursor == cfrag.precursor
        assert new_cfrag.verify(capsule,
                                signing_pk=verifying_pk,
                                delegating_pk=delegating_pk,
                                receiving_pk=receiving_pk,
                                metadata=metadata)
