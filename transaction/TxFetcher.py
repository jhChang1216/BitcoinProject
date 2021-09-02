from transaction.Tx import Tx
from selenium import webdriver
from io import BytesIO
from lib.helper import little_endian_to_int, hash256

class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            url = 'https://tbtc.bitaps.com/raw/transaction/'
        else:
            url = 'https://btc.bitaps.com/raw/transaction/'
        return url

    @classmethod
    def fetch(cls, tx_id, testnet=False):
        url = cls.get_url(testnet)
        driver = webdriver.Chrome(executable_path='chromedriver')
        url = url+f'{tx_id}'
        driver.get(url=url)

        raw = driver.find_element_by_id('raw-tx').text
        raw = bytes.fromhex(raw)
        driver.quit()

        tx = Tx.parse(BytesIO(raw), testnet=testnet)

        # if raw[4] == 0:
        #     raw = raw[:4] + raw[6:]
        #     tx = Tx.parse(BytesIO(raw), testnet=testnet)
        #     tx.locktime = little_endian_to_int(raw[-4:])
        # else:
        #     tx = Tx.parse(BytesIO(raw), testnet=testnet)
        return tx

