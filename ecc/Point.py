class Point:

    def __init__(self, x, y, a, b):
        self.x = x
        self.y = y
        self.a = a
        self.b = b
        if x is None and y is None:
            return
        if self.y**2 != self.x**3 + self.a*self.x + self.b:
            raise ValueError('({},{}) is not on the curve'.format(x,y))

    def __repr__(self):
        return 'Point({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y and self.a == other.a and self.b == other.b

    def __ne__(self, other):
        return self.x != other.x or self.y != other.y or self.a != other.a or self.b != other.b

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError('Points {}, {} are not on the same curve'.format(self, other))
        if self.x is None:
            return other
        elif other.x is None:
            return self
        if self.x == other.x and self.y != other.y:
            return self.__class__(None,None,self.a,self.b)
        if self.x != other.x:
            slope = (self.y - other.y)/(self.x - other.x)
            x3 = slope ** 2 - self.x - other.x
            y3 = slope * (self.x - x3) - self.y
            return self.__class__(x3, y3, self.a, self.b)
        elif self == other:
            if self.y == 0 and other.y==0:
                return self.__class__(None,None,self.a,self.b)
            slope = (3*self.x**2 + self.a)/(2*self.y)
            x3 = slope**2 - 2*self.x
            y3 = slope*(self.x - x3) - self.y
            return self.__class__(x3,y3, self.a, self.b)

    def __rmul__(self, coefficient):
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result