from ecc.FieldElement import FieldElement
from ecc.Point import Point

P = 2 ** 256 - 2 ** 32 - 977

class S256Field(FieldElement):
    def __init__(self, num, prime=None):
        super().__init__(num, prime=P)

    def __repr__(self):
        return '{:x}'.format(self.num).zfill(64)

    def sqrt(self):
        return self ** ((P + 1) // 4)