from scripts.Script import Script
from lib.helper import little_endian_to_int, int_to_little_endian

class TxIn:
    def __init__(self, prev_tx, prev_idx, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_idx = prev_idx
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return '{}:{}\nScript_sig : {}'.format(
            self.prev_tx.hex(),
            self.prev_idx,
            self.script_sig
        )

    def serialize(self):
        result = self.prev_tx[::-1] ##트랜잭션 ID는 이미 hex값이라 거꾸로하면 리틀엔디언이 됨
        result += int_to_little_endian(self.prev_idx, 4) #int형 이전 트랜잭션 인덱스를 리틀엔디언으로 변환
        result += self.script_sig.serialize() #해제 스크립트를 자체적으로 직렬화
        result += int_to_little_endian(self.sequence, 4) #int형 시퀀스를 리틀엔디언으로 변환
        return result


    @classmethod
    def parse(cls, strm):
        prev_tx = strm.read(32)[::-1]  ##32바이트 리틀엔디언을 읽어들여서 거꾸로 --> 정수형
        prev_idx = little_endian_to_int(strm.read(4))  ## 정수형 4바이트 읽은 리틀엔디언 --> 정수형
        script_sig = Script.parse(strm)
        sequence = little_endian_to_int(strm.read(4))
        return cls(prev_tx, prev_idx, script_sig, sequence)

    def fetch_tx(self, testnet=False):
        from transaction.TxFetcher import TxFetcher
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False):
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_idx].amount

    def script_pubkey(self, testnet=False):
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_idx].script_pubkey


