from ecc.FieldElement import FieldElement
from ecc.Point import Point
from ecc.S256Field import S256Field
from lib.helper import hash160, hash256, encode_base58_checksum

A = 0
B = 7
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
P = 2**256 - 2 ** 32 - 977

class S256Point(Point):
    def __init__(self, x, y, a = None, b = None):
        a = S256Field(A)
        b = S256Field(B)
        if type(x) == int:
            x = S256Field(x)
            y = S256Field(y)
            super().__init__(x, y, a, b)
        else:
            super().__init__(x, y, a, b)

    def __repr__(self):
        if self.x is None:
            return 'S256Point(infinity)'
        else:
            return 'S256Point({}, {})'.format(self.x, self.y)


    def sec(self, compressed=True):
        if compressed:
            if self.y.num%2 == 0:
                return b'\x02'+self.x.num.to_bytes(32,'big')
            else:
                return b'\x03'+self.x.num.to_bytes(32,'big')
        return b'\x04'+self.x.num.to_bytes(32, 'big') \
               + self.y.num.to_bytes(32,'big')

    @classmethod
    def parse(cls, sec_bin):
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33:65], 'big')
            return S256Point(x=x,y=y)
        is_even = sec_bin[0] == 2  # True 혹은 False
        x = S256Field(int.from_bytes(sec_bin[1:], 'big'))
        alpha = x ** 3 + S256Field(B) 
        beta = alpha.sqrt()  # y값을 구한다
        if beta.num % 2 == 0:
            even_beta = beta  # y는 짝수
            odd_beta = S256Field(P - beta.num)  # p-y는 홀수
        else:
            even_beta = S256Field(P - beta.num) # p-y는 짝수
            odd_beta = beta  # y는 홀수
        if is_even:
            return S256Point(x, even_beta)  # x, 짝수인 y 반환
        else:
            return S256Point(x, odd_beta) # x, 홀수인 y 반환

    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))

    def address(self, compressed=True, testnet=False):
        h160 = self.hash160(compressed)
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return encode_base58_checksum(prefix+h160)


