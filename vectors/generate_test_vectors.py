import json
import os

from umbral import SecretKey, PublicKey, Signer, encrypt, generate_kfrags, reencrypt
from umbral.curve_scalar import CurveScalar
from umbral.curve_point import  CurvePoint
from umbral.hashing import Hash, unsafe_hash_to_point
from umbral.dem import DEM, kdf


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
generate_again = True

#########
# SETUP #
#########

# We create also some Umbral objects for later
delegating_sk = SecretKey.random()
receiving_sk = SecretKey.random()
signing_sk = SecretKey.random()

verifying_pk = PublicKey.from_secret_key(signing_sk)
delegating_pk = PublicKey.from_secret_key(delegating_sk)
receiving_pk = PublicKey.from_secret_key(receiving_sk)

kfrags = generate_kfrags(delegating_sk=delegating_sk,
                         receiving_pk=receiving_pk,
                         signer=Signer(signing_sk),
                         threshold=6,
                         num_kfrags=10,
                         )

plain_data = b'peace at dawn'

capsule, ciphertext = encrypt(delegating_pk, plain_data)

cfrag = reencrypt(capsule, kfrags[0])
points = [capsule.point_e, cfrag.point_e1, cfrag.proof.point_e2,
          capsule.point_v, cfrag.point_v1, cfrag.proof.point_v2,
          cfrag.proof.kfrag_commitment, cfrag.proof.kfrag_pok]

z = cfrag.proof.signature


###########################
# CurveScalar arithmetics #
###########################

# Let's generate two random CurveScalars
bn1 = CurveScalar.random_nonzero()
bn2 = CurveScalar.random_nonzero()

# Expected results for some binary operations
expected = [('Addition', bn1 + bn2),
            ('Subtraction', bn1 - bn2),
            ('Multiplication', bn1 * bn2),
            ('Inverse', bn1.invert()),
            ]

expected = [{'operation': op, 'result': hexlify(result)} for (op, result) in expected]

# Definition of test vector
vector_suite = {
    'name': 'Test vectors for CurveScalar operations',
    'params': 'default',
    'first operand': hexlify(bn1),
    'second operand': hexlify(bn2),
    'vectors': expected
}

json_file = 'vectors_scalar_operations.json'

create_test_vector_file(vector_suite, json_file, generate_again=generate_again)



###############################
# CurveScalar.from_digest()   #
###############################

# Test vectors for different kinds of inputs (bytes, CurvePoints, CurveScalars, etc.)
inputs = ([b''],
          [b'abc'],
          [capsule.point_e],
          [z],
          [capsule.point_e, z],
          points,
          )

vectors = list()
for input_to_hash in inputs:
    digest = Hash(b'some_dst')
    for input_ in input_to_hash:
        digest.update(input_)
    scalar = CurveScalar.from_digest(digest)
    json_input = [{'class': data.__class__.__name__,
                   'bytes': hexlify(data),
                   } for data in input_to_hash]

    json_input = {'input': json_input, 'output': hexlify(scalar) }

    vectors.append(json_input)

vector_suite = {
    'name' : 'Test vectors for umbral.curvebn.CurveScalar.from_digest()',
    'params' : 'default',
    'vectors' : vectors
}

create_test_vector_file(vector_suite, 'vectors_scalar_from_digest.json', generate_again=generate_again)
#print(json.dumps(vector_suite, indent=2))


###############
# CurvePoints #
###############

point1 = CurvePoint.random()
point2 = CurvePoint.random()

# Expected results for some CurvePoint operations
expected = [('Addition', point1 + point2),
            ('Subtraction', point1 - point2),
            ('Multiplication', point1 * bn1),
            ('Inversion', -point1),
            ('To_affine.X', point1.to_affine()[0]),
            ('To_affine.Y', point1.to_affine()[1]),
            ('kdf', kdf(bytes(point1), DEM.KEY_SIZE)),
            ]

expected = [{'operation': op, 'result': hexlify(result)} for (op, result) in expected]

# Definition of test vector
vector_suite = {
    'name': 'Test vectors for CurvePoint operations',
    'params': 'default',
    'first CurvePoint operand': hexlify(point1),
    'second CurvePoint operand': hexlify(point2),
    'CurveScalar operand': hexlify(bn1),
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
    for dst in inputs:
        point = unsafe_hash_to_point(dst=dst, data=data)
        json_input = {'data': hexlify(data),
                      'dst': hexlify(dst),
                      'point': hexlify(point),
                      }

        vectors.append(json_input)

vector_suite = {
    'name': 'Test vectors for unsafe_hash_to_point()',
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
    assert kfrag.verify(verifying_pk, delegating_pk, receiving_pk)

    json_input = {'kfrag': hexlify(kfrag)}

    vectors.append(json_input)

vector_suite = {
    'name': 'Test vectors for KFrags',
    'description': ('This is a collection of KFrags generated under the '
                    'enclosed delegating, verifying and receiving keys. '
                    'Each of them must deserialize correctly and the '
                    'call to verify() must succeed.'),
    'params': 'default',
    'verifying_pk': hexlify(verifying_pk),
    'delegating_pk': hexlify(delegating_pk),
    'receiving_pk': hexlify(receiving_pk),
    'vectors': vectors
}

#print(json.dumps(vector_suite, indent=2))
create_test_vector_file(vector_suite, 'vectors_kfrags.json', generate_again=generate_again)


##########
# CFrags #
##########

vectors = list()

metadata = b'kfrag_metadata'
for kfrag in kfrags:
    cfrag = reencrypt(capsule, kfrag, metadata)
    json_input = {'kfrag': hexlify(kfrag), 'cfrag': hexlify(cfrag)}
    vectors.append(json_input)

vector_suite = {
    'name': 'Test vectors for CFrags',
    'description': ('This is a collection of CFrags, originated from the '
                    'enclosed Capsule, under the enclosed delegating, '
                    'verifying and receiving keys. Each CFrag must deserialize '
                    'correctly and can be replicated with a call to '
                    '`reencrypt(kfrag, capsule, , b\'kfrag_metadata\')`'),
    'params': 'default',
    'capsule': hexlify(capsule),
    'metadata': hexlify(metadata),
    'verifying_pk': hexlify(verifying_pk),
    'delegating_pk': hexlify(delegating_pk),
    'receiving_pk': hexlify(receiving_pk),
    'vectors': vectors
}

#print(json.dumps(vector_suite, indent=2))
create_test_vector_file(vector_suite, 'vectors_cfrags.json', generate_again=generate_again)
