from scripts.Script import Script
from lib.helper import little_endian_to_int
from lib.helper import int_to_little_endian

class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    # def __repr__(self):
    #     return '{}:{}'.format(self.amount, self.script_pubkey)

    def __repr__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey)

    def serialize(self):
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result

    @classmethod
    def parse(cls, strm):
        amount = little_endian_to_int(strm.read(8))
        script_pubkey = Script.parse(strm)
        return cls(amount, script_pubkey)

