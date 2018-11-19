import json
import os

from umbral import pre
from umbral.keys import UmbralPrivateKey
from umbral.signing import Signer
from umbral.curvebn import CurveBN
from umbral.point import Point
from umbral.random_oracles import hash_to_curvebn, unsafe_hash_to_point
from umbral.config import set_default_curve, default_params


#######################
# Auxiliary functions #
#######################

def hexlify(data):
    if isinstance(data, int):
        return hex(data)[2:]
    try:
        return data.to_bytes().hex()
    except AttributeError:
        return bytes(data).hex()


def create_test_vector_file(vector, filename, generate_again=False):
    path = os.path.join(os.path.dirname(__file__), filename)

    mode = 'w' if generate_again else 'x'
    try:
        with open(path, mode) as f:
            json.dump(vector, f, indent=2)
    except FileExistsError:
        pass


# If True, this will overwrite existing test vector files with new randomly generated instances
generate_again = False

#########
# SETUP #
#########
set_default_curve()
params = default_params()
curve = params.curve

# We create also some Umbral objects for later
delegating_privkey = UmbralPrivateKey.gen_key(params=params)
receiving_privkey = UmbralPrivateKey.gen_key(params=params)
signing_privkey = UmbralPrivateKey.gen_key(params=params)

verifying_key = signing_privkey.get_pubkey()
delegating_key = delegating_privkey.get_pubkey()
receiving_key = receiving_privkey.get_pubkey()

signer = Signer(signing_privkey)

kfrags = pre.generate_kfrags(delegating_privkey=delegating_privkey,
                             receiving_pubkey=receiving_key,
                             threshold=6,
                             N=10,
                             signer=signer,
                             )

plain_data = b'peace at dawn'

ciphertext, capsule = pre.encrypt(delegating_key, plain_data)

capsule.set_correctness_keys(delegating=delegating_key,
                             receiving=receiving_key,
                             verifying=verifying_key)

cfrag = pre.reencrypt(kfrags[0], capsule)
points = [capsule.point_e, cfrag.point_e1, cfrag.proof.point_e2,
          capsule.point_v, cfrag.point_v1, cfrag.proof.point_v2,
          capsule.params.u, cfrag.proof.point_kfrag_commitment, cfrag.proof.point_kfrag_pok]

z = cfrag.proof.bn_sig


#######################
# CurveBN arithmetics #
#######################

# Let's generate two random CurveBNs
bn1 = CurveBN.gen_rand(curve)
bn2 = CurveBN.gen_rand(curve)

# Expected results for some binary operations
expected = [('Addition', bn1 + bn2),
            ('Subtraction', bn1 - bn2),
            ('Multiplication', bn1 * bn2),
            ('Division', bn1 / bn2),
            ('Pow', bn1 ** bn2),
            ('Mod', bn1 % bn2),
            ('Inverse', ~bn1),
            ('Neg', -bn1),
            ]

expected = [{'operation': op, 'result': hexlify(result)} for (op, result) in expected]

# Definition of test vector
vector_suite = {
    'name': 'Test vectors for CurveBN operations',
    'params': 'default',
    'first operand': hexlify(bn1),
    'second operand': hexlify(bn2),
    'vectors': expected
}

json_file = 'vectors_curvebn_operations.json'

create_test_vector_file(vector_suite, json_file, generate_again=generate_again)



###################
# hash_to_curvebn #
###################

# Test vectors for different kinds of inputs (bytes, Points, CurveBNs, etc.)
inputs = ([b''],
          [b'abc'],
          [capsule.point_e],
          [z],
          [capsule.point_e, z],
          points,
          )

vectors = list()
for input_to_hash in inputs:
    bn_output = hash_to_curvebn(*input_to_hash, params=params)
    json_input = [{'class': data.__class__.__name__,
                   'bytes': hexlify(data),
                   } for data in input_to_hash]

    json_input = {'input': json_input, 'output': hexlify(bn_output) }

    vectors.append(json_input)

vector_suite = {
    'name' : 'Test vectors for umbral.curvebn.CurveBN.hash()',
    'params' : 'default',
    'vectors' : vectors
}

create_test_vector_file(vector_suite, 'vectors_curvebn_hash.json', generate_again=generate_again)
#print(json.dumps(vector_suite, indent=2))


##########
# Points #
##########

point1 = Point.gen_rand(curve)
point2 = Point.gen_rand(curve)

# Expected results for some Point operations
expected = [('Addition', point1 + point2),
            ('Subtraction', point1 - point2),
            ('Multiplication', bn1 * point1),
            ('Inversion', -point1),
            ('To_affine.X', point1.to_affine()[0]),
            ('To_affine.Y', point1.to_affine()[1]),
            ]

expected = [{'operation': op, 'result': hexlify(result)} for (op, result) in expected]

# Definition of test vector
vector_suite = {
    'name': 'Test vectors for Point operations',
    'params': 'default',
    'first Point operand': hexlify(point1),
    'second Point operand': hexlify(point2),
    'CurveBN operand': hexlify(bn1),
    'vectors': expected
}

json_file = 'vectors_point_operations.json'

create_test_vector_file(vector_suite, json_file, generate_again=generate_again)


########################
# unsafe_hash_to_point #
########################

inputs = (b'',
          b'abc',
          b'NuCypher',
          b'Nucypher',
         )

vectors = list()
for data in inputs:
    for label in inputs:
        point = unsafe_hash_to_point(label=label, data=data, params=params)
        json_input = {'data': hexlify(data),
                      'label': hexlify(label),
                      'point': hexlify(point),
                      }

        vectors.append(json_input)

vector_suite = {
    'name': 'Test vectors for umbral.point.Point.unsafe_hash_to_point',
    'params': 'default',
    'vectors': vectors
}

create_test_vector_file(vector_suite, 'vectors_unsafe_hash_to_point.json', generate_again=generate_again)
#print(json.dumps(vector_suite, indent=2))


##########
# KFrags #
##########

vectors = list()
for kfrag in kfrags:
    assert kfrag.verify(verifying_key, delegating_key, receiving_key)

    json_input = {'kfrag': hexlify(kfrag)}

    vectors.append(json_input)

vector_suite = {
    'name': 'Test vectors for KFrags',
    'description': ('This is a collection of KFrags generated under the ' 
                    'enclosed delegating, verifying and receiving keys. '
                    'Each of them must deserialize correctly and the '
                    'call to verify() must succeed.'),
    'params': 'default',
    'verifying_key': hexlify(verifying_key),
    'delegating_key': hexlify(delegating_key),
    'receiving_key': hexlify(receiving_key),
    'vectors': vectors
}

#print(json.dumps(vector_suite, indent=2))
create_test_vector_file(vector_suite, 'vectors_kfrags.json', generate_again=generate_again)


##########
# CFrags #
##########

capsule.set_correctness_keys(delegating=delegating_key,
                             receiving=receiving_key,
                             verifying=verifying_key)

vectors = list()

for kfrag in kfrags:
    cfrag = pre.reencrypt(kfrag, capsule, provide_proof=False)
    json_input = {'kfrag': hexlify(kfrag), 'cfrag': hexlify(cfrag)}
    vectors.append(json_input)

vector_suite = {
    'name': 'Test vectors for CFrags',
    'description': ('This is a collection of CFrags, originated from the '
                    'enclosed Capsule, under the enclosed delegating, '
                    'verifying and receiving keys. Each CFrag must deserialize '
                    'correctly and can be replicated with a call to '
                    '`pre.reencrypt(kfrag, capsule, provide_proof=False)`'),
    'params': 'default',
    'capsule': hexlify(capsule),
    'verifying_key': hexlify(verifying_key),
    'delegating_key': hexlify(delegating_key),
    'receiving_key': hexlify(receiving_key),
    'vectors': vectors
}

#print(json.dumps(vector_suite, indent=2))
create_test_vector_file(vector_suite, 'vectors_cfrags.json', generate_again=generate_again) 




