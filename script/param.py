import sys
sys.path.append("/Users/zhenfei/Documents/GitHub/bls_sigs_ref/python-impl")

import hkdf
import hashlib

from hashlib import sha256
from consts import q
from hash_to_field import hash_to_field
from util import print_g1_hex, print_g2_hex, prepare_msg
from opt_swu_g1 import map2curve_osswu
from opt_swu_g2 import map2curve_osswu2
from serdes import serialize
from curve_ops import g1gen


# constants
DOM_SEP_PARAM_GEN  = bytes("Pixel public parameter generation", "ascii")
seed = bytes("3.\
1415926535897932384626433832795028841971693993751058209749445923\
0781640628620899862803482534211706798214808651328230664709384460\
9550582231725359408128481117450284102701938521105559644622948954\
9303819644288109756659334461284756482337867831652712019091456485\
6692346034861045432664821339360726024914127372458700660631558817\
4881520920962829254091715364367892590360011330530548820466521384\
1469519415116094330572703657595919530921861173819326117931051185\
4807446237996274956735188575272489122793818301194912983367336244\
0656643086021394946395224737190702179860943702770539217176293176\
7523846748184676694051320005681271452635608277857713427577896091\
7363717872146844090122495343014654958537105079227968925892354201\
9956112129021960864034418159813629774771309960518707211349999998\
3729780499510597317328160963185950244594553469083026425223082533\
4468503526193118817101000313783875288658753320838142061717766914\
7303598253490428755468731159562863882353787593751957781857780532\
171226806613001927876611195909216420198", "ascii")
ciphersuite = 0
d = 32

# extract the secret m
m = hkdf.hkdf_extract(salt=DOM_SEP_PARAM_GEN, input_key_material=seed, hash=hashlib.sha256);

# generate h using hash_to_group
info = bytes("H2G_h", "ascii")
# expand the secret
key = hkdf.hkdf_expand(pseudo_random_key=m, info=info, length=32, hash=hashlib.sha256)
# hash to G2
h = map2curve_osswu2(prepare_msg(key, ciphersuite))

# generate hlistusing hash_to_group
hlist =[]
for i in range(d+1):
    infos  = "H2G_h%c"%i
    info  = bytes(infos, "ascii")
    # expand the secret
    key = hkdf.hkdf_expand(pseudo_random_key=m, info=info, length=32, hash=hashlib.sha256)
    # hash to G2
    hi = map2curve_osswu2(prepare_msg(key, ciphersuite))
    hlist.append(hi)

# formulate the outputs
buf = b"%c" % ciphersuite
buf = buf + b"%c" % d
buf = buf + serialize(g1gen, False)
buf = buf + serialize(h, False)
for i in range(d+1):
    buf = buf + serialize(hlist[i], False)

# write to the output
f = open("kat_python.txt", "wb")
f.write(buf)
f.close()
