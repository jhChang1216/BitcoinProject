from keys.PrivateKey import PrivateKey
from ecc.S256Point import S256Point
from lib.helper import hash256, hash160, merkle_parent, merkle_root, merkle_parent_level
from keys.Verify import Verify
from transaction.TxFetcher import TxFetcher
from scripts.Script import Script
from merkleblock.MerkleTree import MerkleTree

G = S256Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
              0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

if __name__ == '__main__':

    # e = int.from_bytes(hash256(b"Project_Shawshank"), 'big')
    # z = int.from_bytes(hash256(b'Latte_is_a_horse.'), 'big')
    # pv_key = PrivateKey(e)
    # pubkey = pv_key.point
    # sig = pv_key.sign(z)
    # print('message z : ', z)
    # print('private key : ', pv_key)
    # print('public key : ', pubkey)
    # print('signature : ', sig)
    #
    # print(Verify.sig_verify(sig, z, pubkey))

    # tx_id = 'a571dd4a6d7282f4005daa21ceca8681b714d1fc94b5b6ebd49f1832207b8985'


    ############################################################################################################
    # tx_ids = ['4c79447db1ec334996137e71d356434479b25c77462e56b9058d9f51d6a100c0',
    #           '8c93d4d6d3993442a1b1540add3fb9c6a3e11eda24d231af19cfc8c440ab96b7',
    #           'd5c528b713816f7dbd13347631852b2427e05c4d370eee96983ed444e7861e92',
    #           '6a084548916db14931a0189ef7864ddf002576683edecbbc56cf21007bcb920b',
    #           '8c93d4d6d3993442a1b1540add3fb9c6a3e11eda24d231af19cfc8c440ab96b7']
    #
    # tx_hash = 'd5c528b713816f7dbd13347631852b2427e05c4d370eee96983ed444e7861e92'
    # tx = TxFetcher.fetch(tx_hash, testnet=False)
    # print(tx.verify())
    #
    # print(tx)
    #
    # tx2 = TxFetcher.fetch('2eab7cf416d430a1803145478894c4c62beeb0ae86f2fa574509118e023ca021', testnet=False)
    # print(tx2)
    ###################################################################################################################

    hex_hashes = [
        'c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5',
        'c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5',
        'f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0',
        '3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181',
        '10092f2633be5f3ce349bf9ddbde36caa3dd10dfa0ec8106bce23acbff637dae',
        '7d37b3d54fa6a64869084bfd2e831309118b9e833610e6228adacdbd1b4ba161',
        '8118a77e542892fe15ae3fc771a4abfd2f5d5d5997544c3487ac36b5c85170fc',
        'dff6879848c2c9b62fe652720b8df5272093acfaa45a43cdb3696fe2466a3877',
        'b825c0745f46ac58f7d3759e6dc535a1fec7820377f24d4c2c6ad2cc55c0cb59',
        '95513952a04bd8992721e9b7e2937f1c04ba31e0469fbe615a78197f68f52b7c',
        '2e6d722e5e4dbdf2447ddecc9f7dabb8e299bae921c99ad5b0184cd9eb8e5908',
        'b13a750047bc0bdceb2473e5fe488c2596d7a7124b4e716fdd29b046ef99bbf0',
    ]

    print(merkle_root(hex_hashes))

    merkle_tree = MerkleTree(len(hex_hashes))
    merkle_tree.nodes[4] = [bytes.fromhex(h) for h in hex_hashes]
    merkle_tree.nodes[3] = merkle_parent_level(merkle_tree.nodes[4])
    merkle_tree.nodes[2] = merkle_parent_level(merkle_tree.nodes[3])
    merkle_tree.nodes[1] = merkle_parent_level(merkle_tree.nodes[2])
    merkle_tree.nodes[0] = merkle_parent_level(merkle_tree.nodes[1])
    print(merkle_tree)



















