from lib.helper import (
    little_endian_to_int,
    int_to_little_endian,
    hash256,
    bits_to_target,
    merkle_root)

class Block:

    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce, tx_hashes=None):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.tx_hashes = tx_hashes

    @classmethod
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        prev_block = s.read(32)[::-1]
        merkle_root = s.read(32)[::-1]
        timestamp = little_endian_to_int(s.read(4))
        bits = s.read(4)
        nonce = s.read(4)
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += self.prev_block[::-1]
        result += self.merkle_root[::-1]
        result += int_to_little_endian(self.timestamp, 4)
        result += self.bits
        result += self.nonce
        return result

    def hash(self):
        h256 = hash256(self.serialize())
        return h256[::-1]

    def target(self):
        return bits_to_target(self.bits)

    def difficulty(self):
        target = self.target()
        difficulty = 0xffff*256**(0x1d-3)/target
        return difficulty

    def check_pow(self):
        sha = hash256(self.serialize())
        proof = little_endian_to_int(sha)
        target = self.target()
        return proof < target

    def validate_merkle_root(self):
        tx_hashes = [h[::-1] for h in self.tx_hashes]
        mk_root = merkle_root(tx_hashes)[::-1]
        return mk_root == self.merkle_root

