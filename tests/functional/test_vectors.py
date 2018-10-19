"""
Copyright (C) 2018 NuCypher

This file is part of pyUmbral.

pyUmbral is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

pyUmbral is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pyUmbral. If not, see <https://www.gnu.org/licenses/>.
"""

import json
import os

from umbral.curvebn import CurveBN
from umbral.point import Point
from umbral.keys import UmbralPublicKey
from umbral.config import default_params
from umbral.kfrags import KFrag
from umbral.cfrags import CapsuleFrag
from umbral.random_oracles import hash_to_curvebn, unsafe_hash_to_point
from umbral import pre

def test_curvebn_operations():

    vector_file = os.path.join('vectors', 'vectors_curvebn_operations.json')
    try:
        with open(vector_file) as f:
            vector_suite = json.load(f)
    except OSError:
        raise 

    bn1 = CurveBN.from_bytes(bytes.fromhex(vector_suite['first operand']))
    bn2 = CurveBN.from_bytes(bytes.fromhex(vector_suite['second operand']))

    expected = dict()
    for op_result in vector_suite['vectors']:
        result = bytes.fromhex(op_result['result'])
        expected[op_result['operation']] = CurveBN.from_bytes(result)

    test = [('Addition', bn1 + bn2),
            ('Subtraction', bn1 - bn2),
            ('Multiplication', bn1 * bn2),
            ('Division', bn1 / bn2),
            ('Pow', bn1 ** bn2),
            ('Mod', bn1 % bn2),
            ('Inverse', ~bn1),
            ('Neg', -bn1),
            ]

    for (operation, result) in test:
        assert result == expected[operation], 'Error in {}'.format(operation)

def test_curvebn_hash():

    vector_file = os.path.join('vectors', 'vectors_curvebn_hash.json')
    try:
        with open(vector_file) as f:
            vector_suite = json.load(f)
    except OSError:
        raise 

    params = default_params()

    for vector in vector_suite['vectors']:
        hash_input = [bytes.fromhex(item['bytes']) for item in vector['input']]
        expected = CurveBN.from_bytes(bytes.fromhex(vector['output']))
        assert hash_to_curvebn(*hash_input, params=params) == expected


def test_point_operations():

    vector_file = os.path.join('vectors', 'vectors_point_operations.json')
    try:
        with open(vector_file) as f:
            vector_suite = json.load(f)
    except OSError:
        raise 

    point1 = Point.from_bytes(bytes.fromhex(vector_suite['first Point operand']))
    point2 = Point.from_bytes(bytes.fromhex(vector_suite['second Point operand']))
    bn1 = CurveBN.from_bytes(bytes.fromhex(vector_suite['CurveBN operand']))

    expected = dict()
    for op_result in vector_suite['vectors']:
        expected[op_result['operation']] = bytes.fromhex(op_result['result'])

    test = [('Addition', point1 + point2),
            ('Subtraction', point1 - point2),
            ('Multiplication', bn1 * point1),
            ('Inversion', -point1),
            ]

    for (operation, result) in test:
        assert result == Point.from_bytes(expected[operation]), 'Error in {}'.format(operation)

    test = [('To_affine.X', point1.to_affine()[0]),
            ('To_affine.Y', point1.to_affine()[1]),
            ]

    for (operation, result) in test:
        assert result == int.from_bytes(expected[operation], 'big'), 'Error in {}'.format(operation)


def test_unsafe_hash_to_point():

    vector_file = os.path.join('vectors', 'vectors_unsafe_hash_to_point.json')
    try:
        with open(vector_file) as f:
            vector_suite = json.load(f)
    except OSError:
        raise 

    params = default_params()

    for item in vector_suite['vectors']:
        data = bytes.fromhex(item['data'])
        label = bytes.fromhex(item['label'])
        expected = Point.from_bytes(bytes.fromhex(item['point']))
        assert expected == unsafe_hash_to_point(label=label, data=data, params=params)


def test_kfrags():

    vector_file = os.path.join('vectors', 'vectors_kfrags.json')
    try:
        with open(vector_file) as f:
            vector_suite = json.load(f)
    except OSError:
        raise 

    verifying_key = UmbralPublicKey.from_bytes(bytes.fromhex(vector_suite['verifying_key']))
    delegating_key = UmbralPublicKey.from_bytes(bytes.fromhex(vector_suite['delegating_key']))
    receiving_key = UmbralPublicKey.from_bytes(bytes.fromhex(vector_suite['receiving_key']))

    for json_kfrag in vector_suite['vectors']:
        kfrag = KFrag.from_bytes(bytes.fromhex(json_kfrag['kfrag']))
        assert kfrag.verify(signing_pubkey=verifying_key,
                            delegating_pubkey=delegating_key,
                            receiving_pubkey=receiving_key), \
            'Invalid KFrag {}'.format(kfrag.to_bytes().hex())


def test_cfrags():

    vector_file = os.path.join('vectors', 'vectors_cfrags.json')
    try:
        with open(vector_file) as f:
            vector_suite = json.load(f)
    except OSError:
        raise 

    params = default_params()

    capsule = pre.Capsule.from_bytes(bytes.fromhex(vector_suite['capsule']),
                                     params=params)

    verifying_key = UmbralPublicKey.from_bytes(bytes.fromhex(vector_suite['verifying_key']))
    delegating_key = UmbralPublicKey.from_bytes(bytes.fromhex(vector_suite['delegating_key']))
    receiving_key = UmbralPublicKey.from_bytes(bytes.fromhex(vector_suite['receiving_key']))

    kfrags_n_cfrags = [(KFrag.from_bytes(bytes.fromhex(json_kfrag['kfrag'])),
                        CapsuleFrag.from_bytes(bytes.fromhex(json_kfrag['cfrag'])))
                       for json_kfrag in vector_suite['vectors']]

    capsule.set_correctness_keys(delegating=delegating_key,
                                 receiving=receiving_key,
                                 verifying=verifying_key)

    for kfrag, cfrag in kfrags_n_cfrags:
        assert kfrag.verify(signing_pubkey=verifying_key,
                            delegating_pubkey=delegating_key,
                            receiving_pubkey=receiving_key), \
            'Invalid KFrag {}'.format(kfrag.to_bytes().hex())

        new_cfrag = pre.reencrypt(kfrag, capsule, provide_proof=False)
        assert new_cfrag.point_e1 == cfrag.point_e1
        assert new_cfrag.point_v1 == cfrag.point_v1
        assert new_cfrag.kfrag_id == cfrag.kfrag_id
        assert new_cfrag.point_precursor == cfrag.point_precursor
        assert new_cfrag.proof is None
        assert cfrag.to_bytes() == new_cfrag.to_bytes()
