from transaction.Tx import Tx
from selenium import webdriver
from io import BytesIO
from lib.helper import little_endian_to_int,int_to_little_endian

class Scraper:

    @classmethod
    def get_url(cls, tx_id, testnet=False):
        if testnet:
            url = 'https://blockchair.com/bitcoin/testnet/'
        else:
            url = 'https://blockchair.com/bitcoin/'
        url += f'tx/{tx_id}'
        return url

    @classmethod
    def fetch(cls, tx_id, testnet=False):
        url = cls.get_url(tx_id, testnet)
        driver = webdriver.Chrome(executable_path='chromedriver')
        url = f'https://tbtc.bitaps.com/raw/transaction/{tx_id}'
        driver.get(url=url)

        raw = driver.find_element_by_id('raw-tx').text
        raw = bytes.fromhex(raw)
        if raw[4] == 0:
            raw = raw[:4] + raw[6:]
            tx = Tx.parse(BytesIO(raw), testnet=testnet)
            tx.locktime = little_endian_to_int(raw[:-4])
        else:
            tx = Tx.parse(BytesIO(raw), testnet=testnet)
        return tx
        # _int = int(raw, 16)
        # hex_val = hex(_int)
        # print(hex_val)
        #
        # strm = StringIO(hex_val.lstrip('0x'))
        # return type(strm)
        # tx = Tx.parse(strm, testnet=testnet)
        # return tx







