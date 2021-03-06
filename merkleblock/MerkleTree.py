import math

from io import BytesIO
from unittest import TestCase

from lib.helper import (
    bytes_to_bit_field,
    little_endian_to_int,
    merkle_parent,
    read_varint,
)


# tag::source1[]
class MerkleTree:

    def __init__(self, total):
        self.total = total
        self.max_depth = math.ceil(math.log(total, 2))
        nodes = []
        for depth in range(self.max_depth+1):
            num_items = math.ceil(total/2**(self.max_depth-depth))
            level_hashes = [None]*num_items
            nodes.append(level_hashes)
        self.nodes = nodes
        self.current_depth = 0
        self.current_idx = 0

    def __repr__(self):
        result = []
        for depth, level in enumerate(self.nodes):
            items = []
            for idx, h in enumerate(level):
                if h is None:
                    short = 'None'
                else:
                    short = '{}...'.format(h.hex()[:8])
                if depth == self.current_depth and idx == self.current_idx:
                    items.append('*{}*'.format(short[:-2]))
                else:
                    items.append('{}'.format(short))
            result.append(','.join(items))
        return '\n'.join(result)

    def up(self):
        self.current_depth -= 1
        self.current_idx //=2

    def left(self):
        self.current_depth += 1
        self.current_idx *= 2

    def right(self):
        self.current_depth += 1
        self.current_idx = self.current_idx*2 + 1

    def root(self):
        return self.nodes[0][0]

    def set_current_node(self, value):
        self.nodes[self.current_depth][self.current_idx] = value

    def get_current_node(self):
        return self.nodes[self.current_depth][self.current_idx]

    def get_left_node(self):
        return self.nodes[self.current_depth+1][self.current_idx*2]

    def get_right_node(self):
        return self.nodes[self.current_depth+1][self.current_idx*2+1]

    def is_leaf(self):
        return self.current_depth == self.max_depth

    def right_exists(self):
        return len(self.nodes[self.current_depth+1]) > \
            self.current_idx*2 + 1

    def populate_tree(self, flag_bits, hashes):
        while self.root() is None:
            if self.is_leaf():
                flag_bits.pop(0)
                self.set_current_node(hashes.pop())
                self.up()
            else:
                left_hash = self.get_left_node()
                if left_hash is None:
                    if flag_bits.pop(0) == 0:
                        self.set_current_node(hashes.pop(0))
                        self.up()
                    else:
                        self.left()
                elif self.right_exists():
                    right_hash = self.get_right_node()
                    if right_hash is None:
                        self.right()
                    else:
                        self.set_current_node(merkle_parent(left_hash, right_hash))
                        self.up()
                else:
                    self.set_current_node(merkle_parent(left_hash, left_hash))
        if len(hashes) != 0:
            raise RuntimeError('hashes not all consumed {}'.format(len(hashes)))
        for flag_bit in flag_bits:
            if flag_bit != 0:
                raise RuntimeError('flas bits not all consumed')
