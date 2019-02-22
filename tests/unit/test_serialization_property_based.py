"""
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

from cryptography.hazmat.backends.openssl import backend
from hypothesis import HealthCheck, given, settings, unlimited
from hypothesis.strategies import binary, booleans, integers, tuples
from umbral.config import default_curve
from umbral.curvebn import CurveBN
from umbral.cfrags import CorrectnessProof
from umbral.kfrags import KFrag
from umbral.keys import UmbralPrivateKey, UmbralPublicKey
from umbral.params import UmbralParameters
from umbral.point import Point
from umbral.random_oracles import unsafe_hash_to_point
from umbral.pre import Capsule

# test parameters
max_examples = 1000

# crypto constants
curve = default_curve()
params = UmbralParameters(curve)
bn_size = curve.group_order_size_in_bytes

# generators
bns = integers(min_value=1, max_value=backend._bn_to_int(curve.order)).map(
    lambda x: CurveBN.from_int(x))

points = binary(min_size=1).map(
    lambda x: unsafe_hash_to_point(x, label=b'hypothesis', params=params))

signatures = tuples(integers(min_value=1, max_value=backend._bn_to_int(curve.order)),
                 integers(min_value=1, max_value=backend._bn_to_int(curve.order))).map(
                    lambda tup: tup[0].to_bytes(bn_size, 'big') + tup[1].to_bytes(bn_size, 'big'))

# # utility
def assert_kfrag_eq(k0, k1):
    assert(all([ k0.id                  == k1.id
               , k0.bn_key              == k1.bn_key
               , k0.point_precursor     == k1.point_precursor
               , k0.point_commitment    == k1.point_commitment
               , k0.signature_for_bob   == k1.signature_for_bob
               , k0.signature_for_proxy == k1.signature_for_proxy
               ]))

def assert_cp_eq(c0, c1):
    assert(all([ c0.point_e2               == c1.point_e2
               , c0.point_v2               == c1.point_v2
               , c0.point_kfrag_commitment == c1.point_kfrag_commitment
               , c0.point_kfrag_pok        == c1.point_kfrag_pok
               , c0.kfrag_signature        == c1.kfrag_signature
               , c0.bn_sig                 == c1.bn_sig
               , c0.metadata               == c1.metadata
               ]))
  
# tests

@given(bns)
@settings(max_examples=max_examples, timeout=unlimited)
def test_bn_roundtrip(bn):
    assert(bn == CurveBN.from_bytes(bn.to_bytes()))

@given(points, booleans())
@settings(max_examples=max_examples, timeout=unlimited)
def test_point_roundtrip(p, c):
    assert(p == Point.from_bytes(p.to_bytes(is_compressed=c)))

@given(binary(min_size=bn_size, max_size=bn_size), bns, points, points, signatures, signatures)
@settings(max_examples=max_examples, timeout=unlimited)
def test_kfrag_roundtrip(d, b0, p0, p1, sig_proxy, sig_bob):
    k = KFrag(identifier=d, bn_key=b0, point_commitment=p0, point_precursor=p1,
              signature_for_proxy=sig_proxy, signature_for_bob=sig_bob)
    assert_kfrag_eq(k, KFrag.from_bytes(k.to_bytes()))

@given(points, points, bns)
@settings(max_examples=max_examples, timeout=unlimited)
def test_capsule_roundtrip_0(p0, p1, b):
    c = Capsule(params=params, point_e=p0, point_v=p1, bn_sig=b)
    assert(c == Capsule.from_bytes(c.to_bytes(), params=params))

@given(points, points, points, points, bns, signatures)
@settings(max_examples=max_examples, timeout=unlimited)
def test_cp_roundtrip(p0, p1, p2, p3, b0, sig):
    c = CorrectnessProof(p0, p1, p2, p3, b0, sig)
    assert_cp_eq(c, CorrectnessProof.from_bytes(c.to_bytes()))

@given(points)
@settings(max_examples=max_examples, timeout=unlimited)
def test_pubkey_roundtrip(p):
    k = UmbralPublicKey(p, params)
    assert(k == UmbralPublicKey.from_bytes(k.to_bytes(), params=params))

@given(binary(min_size=1))
@settings(max_examples=20, timeout=unlimited, suppress_health_check=[HealthCheck.hung_test])
def test_privkey_roundtrip(p):
    insecure_scrypt_cost = 5   # This is deliberately insecure, just to make it faster
    k = UmbralPrivateKey.gen_key()
    rt = UmbralPrivateKey.from_bytes(k.to_bytes(password=p, _scrypt_cost=insecure_scrypt_cost), 
                                     password=p, 
                                     _scrypt_cost=insecure_scrypt_cost)
    assert(k.get_pubkey() == rt.get_pubkey())