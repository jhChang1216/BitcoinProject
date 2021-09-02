from lib.helper import hash256, SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE
from lib.helper import little_endian_to_int, int_to_little_endian, read_varint, encode_varint
from transaction.TxIn import TxIn
from transaction.TxOut import TxOut
from scripts.Script import Script
from io import BytesIO

CERTIFICATION_CODE = {
    'SIGHASH_ALL' : 1
}

class Tx:
    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False, segwit=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet
        self.segwit = segwit
        self._hash_prevouts = None
        self._hash_sequence = None
        self._hash_outputs = None

    def __repr__(self):
        tx_ins = "\n"
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__()+'\n'
        tx_outs = "\n"
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__()+'\n'
        return 'tx: {}\nversion: {}\ntx_ins: {}\ntx_outs: {}\nlocktime: {}\n{}'.format(
            # self.id(),
            '---- transaction ----',
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
            '---- information ----',
        )

    def id(self):
        return self.hash().hex()

    def hash(self):
        return hash256(self.serialize())[::-1]

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        return result

    # @classmethod
    # def parse(cls, strm, testnet=False):
    #     version = little_endian_to_int(strm.read(4))
    #     num_inputs = read_varint(strm)
    #     print('input은 총 : ',num_inputs)
    #     inputs = []
    #     for _ in range(num_inputs):
    #         print('input parsing!!')
    #         inputs.append(TxIn.parse(strm))
    #
    #     num_outputs = read_varint(strm)
    #     print('output은 총 : ',num_outputs)
    #     outputs = []
    #     for _ in range(num_outputs):
    #         print('output parsing!!')
    #         outputs.append(TxOut.parse(strm))
    #     locktime = little_endian_to_int(strm.read(4))
    #     return cls(version, inputs, outputs, locktime, testnet=testnet)

    @classmethod
    def parse(cls, s, testnet=False):
        s.read(4)  # <1>
        temp = s.read(1)
        if temp == b'\x00':  # <2>
            parse_method = cls.parse_segwit
        else:
            parse_method = cls.parse_legacy
        s.seek(-5, 1)  # <3>
        return parse_method(s, testnet=testnet)

    @classmethod
    def parse_legacy(cls, s, testnet=False):
        print('legacy transaction parsing...')
        version = little_endian_to_int(s.read(4))  # <4>
        num_inputs = read_varint(s)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        num_outputs = read_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime,
                   testnet=testnet, segwit=False)


    @classmethod
    def parse_segwit(cls, s, testnet=False):
        print('segwit transaction parsing...')
        version = little_endian_to_int(s.read(4))
        marker = s.read(2)
        if marker != b'\x00\x01':  # <1>
            raise RuntimeError('Not a segwit transaction {}'.format(marker))
        num_inputs = read_varint(s)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        num_outputs = read_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        for tx_in in inputs:  # <2>
            num_items = read_varint(s)
            items = []
            for _ in range(num_items):
                item_len = read_varint(s)
                if item_len == 0:
                    items.append(0)
                else:
                    items.append(s.read(item_len))
            tx_in.witness = items
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime,
                   testnet=testnet, segwit=True)


    def fee(self):
        input_sum, output_sum = 0, 0
        for tx_in in self.tx_ins:
            input_sum += tx_in.value(self.testnet)
        for tx_out in self.tx_outs:
            output_sum += tx_out.amount
        return input_sum - output_sum

    def sig_hash(self, input_idx, redeem_script=None):
        s = int_to_little_endian(self.version, 4)
        s += encode_varint(len(self.tx_ins))
        for i, tx_in in enumerate(self.tx_ins):
            if i == input_idx:
                if redeem_script:
                    script_sig = redeem_script
                else: script_sig = tx_in.script_pubkey(self.testnet)
            else:
                script_sig = None
            s += TxIn(
                prev_tx = tx_in.prev_tx,
                prev_idx = tx_in.prev_idx,
                script_sig = script_sig,
                sequence=tx_in.sequence,
            ).serialize()
        s+=encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            s+=tx_out.serialize()
        s+= int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SIGHASH_ALL, 4)
        h256 = hash256(s)
        return int.from_bytes(h256, 'big')

    def verify_input(self, input_idx):
        tx_in = self.tx_ins[input_idx]
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
        if script_pubkey.is_p2sh_script_pubkey():
            cmd = tx_in.script_sig.cmd[-1]
            raw_redeem = encode_varint(len(cmd))+cmd
            redeem_script = Script.parse(BytesIO(raw_redeem))
        else:
            redeem_script = None
        z = self.sig_hash(input_idx, redeem_script)
        combined = tx_in.script_sig + script_pubkey
        return combined.evaluate(z)

    def verify(self):
        if self.fee() < 0:
            return False
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True

    def sign_input(self, input_index, private_key):
        z = self.sig_hash(input_index)
        der = private_key.sign(z).der()
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        sec = private_key.point.sec()
        self.tx_ins[input_index].script_sig = Script([sig, sec])
        return self.verify_input(input_index)

    def is_coinbase(self):
        if len(self.tx_ins) != 1:
            return False
        first_input = self.tx_ins[0]
        if first_input.prev_tx != b'\x00' * 32:
            return False
        if first_input.prev_index != 0xffffffff:
            return False
        return True

    def coinbase_height(self):
        if not self.is_coinbase():
            return None
        element = self.tx_ins[0].script_sig.cmds[0]
        return little_endian_to_int(element)





