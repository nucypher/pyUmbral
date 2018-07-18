import json
import os

from umbral.curvebn import CurveBN
from umbral.point import Point
from umbral.config import default_params

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

    test = [  ('Addition', bn1 + bn2),
              ('Subtraction', bn1 - bn2),
              ('Multiplication', bn1 * bn2),
              ('Division', bn1 / bn2), 
              ('Pow', bn1 ** bn2),
              ('Mod', bn1 % bn2),
              ('Inverse', ~bn1),    
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
        assert CurveBN.hash(*hash_input, params=params) == expected


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

    test = [  ('Addition', point1 + point2),
              ('Subtraction', point1 - point2),
              ('Multiplication', bn1 * point1),
              ('Inversion', ~point1), 
           ]

    for (operation, result) in test:
        assert result == Point.from_bytes(expected[operation]), 'Error in {}'.format(operation)

    test = [ ('To_affine.X', point1.to_affine()[0]),
             ('To_affine.Y', point1.to_affine()[1]),
           ]

    for (operation, result) in test:
        assert result == int.from_bytes(expected[operation], 'big'), 'Error in {}'.format(operation)

