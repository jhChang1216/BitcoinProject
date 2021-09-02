from ecc.S256Point import S256Point

G = S256Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
              0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
A = 0
B = 7
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
P = 2**256 - 2 ** 32 - 977

class Verify:

    @classmethod
    def sig_verify(cls, sig, z, pubkey):
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        total = u * G + v * pubkey
        print('calculated r : ', hex(total.x.num))
        return total.x.num == sig.r

