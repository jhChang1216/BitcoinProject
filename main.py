from ecc.FieldElement import FieldElement
from ecc.Point import Point

if __name__ == '__main__':
    element1 = FieldElement(7, 13)
    element2 = FieldElement(8, 13)
    print(element1**(-3) == element2)

    p1 = Point(-1,-1,5,7)
    p2 = Point(-1,-1,5,7)
    print(p1+p2)


