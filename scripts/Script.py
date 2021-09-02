from io import BytesIO
from logging import getLogger
from lib.op import op_equal, op_verify, op_hash160
from unittest import TestCase

from lib.helper import (
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)
from lib.op import (
    OP_CODE_FUNCTIONS,
    OP_CODE_NAMES,
)


LOGGER = getLogger(__name__)


class Script:

    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)

    def __add__(self, other):
        return Script(self.cmds + other.cmds)

    @classmethod
    def parse(cls, s):
        length = read_varint(s)
        cmds = []
        count = 0
        while count < length:
            current = s.read(1)
            count += 1
            current_byte = current[0]
            if current_byte >= 1 and current_byte <= 75:
                n = current_byte
                cmds.append(s.read(n))
                count += n
            elif current_byte == 76:
                # op_pushdata1
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77:
                # op_pushdata2
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                # we have an opcode. set the current byte to op_code
                op_code = current_byte
                # add the op_code to the list of cmds
                cmds.append(op_code)
        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)

    def raw_serialize(self):
        # initialize what we'll send back
        result = b''
        # go through each cmd
        for cmd in self.cmds:
            # if the cmd is an integer, it's an opcode
            if type(cmd) == int:
                # turn the cmd into a single byte integer using int_to_little_endian
                result += int_to_little_endian(cmd, 1)
            else:
                # otherwise, this is an element
                # get the length in bytes
                length = len(cmd)
                # for large lengths, we have to use a pushdata opcode
                if length < 75:
                    # turn the length into a single byte integer
                    result += int_to_little_endian(length, 1)
                elif length > 75 and length < 0x100:
                    # 76 is pushdata1
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif length >= 0x100 and length <= 520:
                    # 77 is pushdata2
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError('too long an cmd')
                result += cmd
        return result

    def serialize(self):
        # get the raw serialization (no prepended length)
        result = self.raw_serialize()
        # get the length of the whole thing
        total = len(result)
        # encode_varint the total length of the result and prepend
        return encode_varint(total) + result

    def evaluate(self, z):
        # create a copy as we may need to add to this list if we have a
        # RedeemScript
        cmds = self.cmds[:]
        stack = []
        altstack = []
        while len(cmds) > 0:
            cmd = cmds.pop(0)
            if type(cmd) == int:
                # do what the opcode says
                operation = OP_CODE_FUNCTIONS[cmd]
                if cmd in (99, 100):
                    # op_if/op_notif require the cmds array
                    if not operation(stack, cmds):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (107, 108):
                    # op_toaltstack/op_fromaltstack require the altstack
                    if not operation(stack, altstack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (172, 173, 174, 175):
                    # these are signing operations, they need a sig_hash
                    # to check against
                    if not operation(stack, z):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                else:
                    if not operation(stack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
            # tag::source1[]
            else:
                stack.append(cmd)
                if len(cmds) == 3 and cmds[0] == 0xa9 \
                    and type(cmds[1]) == bytes and len(cmds[1]) == 20 \
                    and cmds[2] == 0x87:  # <1>
                    cmds.pop()  # <2>
                    h160 = cmds.pop()
                    cmds.pop()
                    if not op_hash160(stack):  # <3>
                        return False
                    stack.append(h160)
                    if not op_equal(stack):
                        return False
                    if not op_verify(stack):  # <4>
                        LOGGER.info('bad p2sh h160')
                        return False
                    redeem_script = encode_varint(len(cmd)) + cmd  # <5>
                    stream = BytesIO(redeem_script)
                    cmds.extend(Script.parse(stream).cmds)  # <6>
        if len(stack) == 0:
            return False
        if stack.pop() == b'':
            return False
        return True


    @classmethod
    def p2pkh_script(cls, h160):
        return Script([0x76, 0xa9, h160, 0x88, 0xac])

    def is_p2sh_script_pubkey(self):
        return len(self.cmds) == 3 and self.cmds[0] == 0xa9 \
            and type(self.cmds[1]) == bytes and len(self.cmds[1]) == 20 \
            and self.cmds[2] == 0x87