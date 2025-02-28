# Copyright (c) 2016-2018, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
# Copyright (c) 2021, the Kevacoin Project Core Developers
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Transaction input and output addresses by tx id.'''

from aiorpcx import run_in_thread

import electrumx.lib.util as util

import json

COINBASE_TX = bytes(32)

class TxDb(object):

    DB_VERSIONS = [0]
    # Only use first 16 bytes of tx hash to save space.
    # The chance of collision is extremely small.
    PARTIAL_TX_HASH = 16

    def __init__(self):
        self.logger = util.class_logger(__name__, self.__class__.__name__)
        self.db_version = max(self.DB_VERSIONS)
        self.db = None

    def open_db(self, db_class, for_sync):
        self.db = db_class('tx_info', for_sync)

    def close_db(self):
        if self.db:
            self.db.close()
            self.db = None

    def put_tx_info(self, tx_hash, tx_info):
        self.db.put(tx_hash[0:self.PARTIAL_TX_HASH], tx_info)

    def put_tx_info_batch(self, tx_info_batch):
        with self.db.write_batch() as batch:
            for tx_hash, tx_info in tx_info_batch.items():
                batch.put(tx_hash[0:self.PARTIAL_TX_HASH], json.dumps(tx_info, separators=(',', ':')).encode())

    def get_tx_info_sync(self, tx_hash):
        return self.db.get(tx_hash[0:self.PARTIAL_TX_HASH])

    async def get_tx_info(self, tx_hash):
        return await run_in_thread(self.db.get, tx_hash[0:self.PARTIAL_TX_HASH])

    def is_coinbase(self, tx_hash):
        return tx_hash == COINBASE_TX

    def Namespace_from_hash160(self, coin, namespace):
        '''Return a coin address given a hash160.'''
        assert len(namespace) == 21
        return coin.ENCODE_CHECK(namespace)

    def add_tx_info(self, coin, tx_list, height, blocktime):
        tx_info_batch = {}

        for tx, _tx_hash in tx_list:
            # For tx info.
            tx_addr_outs = []
            tx_namespace = None
            tx_namespace_vout = 0
            vout = 0
            for txout in tx.outputs:
                value, pk_script = txout
                named_values, address_script = coin.interpret_name_prefix(pk_script, coin.NAME_OPERATIONS)
                if named_values is not None and "name" in named_values:
                    # It is keva namespace
                    tx_namespace = self.Namespace_from_hash160(coin, named_values["name"][1])
                    tx_namespace_vout = vout

                if address_script.startswith(b'\xa9\x14') and len(address_script) == 23:
                    # It is a P2SH script.
                    address = coin.P2SH_address_from_hash160(address_script[2:22])
                    tx_addr_outs = tx_addr_outs + [address, value]
                elif address_script.startswith(b'\x76\xa4\x14') and len(address_script) == 25:
                    # It is P2PKH script
                    address = coin.P2PKH_address_from_hash160(address_script[3:23])
                    tx_addr_outs = tx_addr_outs + [address, value]
                elif address_script.startswith(b'\x6a'):
                    # OP_RETURN
                    address = 'ret'
                    tx_addr_outs = tx_addr_outs + [address, value]
                else:
                    # It may be native witness starts with '\x00\x14' and followed by hash160.
                    # Or completely something else. Put it in the category of "unhandled".
                    address = 'unh' + coin.ENCODE_CHECK(address_script[0:])
                    tx_addr_outs = tx_addr_outs + [address, value]

                vout += 1

            # Only contains outputs. We will add inputs later.
            tx_info_partial = {
                'o': tx_addr_outs,
                't': blocktime,
                'h': height
            }
            if tx_namespace:
                tx_info_partial['n'] = [tx_namespace, tx_namespace_vout]

            tx_info_batch[_tx_hash] = tx_info_partial

        for tx, _tx_hash in tx_list:
            # TxInput(prev_hash=b'\xc1\...', prev_idx=0, script=b'\x16...', sequence=4294967294)
            tx_addr_ins = []
            for txin in tx.inputs:
                prev_hash, prev_idx, _, _ = txin
                if self.is_coinbase(prev_hash):
                    tx_addr_ins = []
                    break

                # Check in-memory tx first.
                prev_tx_info = tx_info_batch.get(prev_hash)
                if prev_tx_info:
                    prev_tx = prev_tx_info['o']
                    prev_addr = prev_tx[2*prev_idx]
                    prev_value = prev_tx[2*prev_idx + 1]
                    tx_addr_ins = tx_addr_ins + [prev_addr, prev_value]
                    continue

                # Not in memory, check the storage
                prev_tx_str = self.get_tx_info_sync(prev_hash)
                if prev_tx_str:
                    prev_tx_info = json.loads(prev_tx_str.decode())
                    prev_tx = prev_tx_info['o']
                    prev_addr = prev_tx[2*prev_idx]
                    prev_value = prev_tx[2*prev_idx + 1]
                    try:
                        index = tx_addr_ins.index(prev_addr)
                    except:
                        index = -1

                    if index >= 0:
                        # For existing address, add the value.
                        tx_addr_ins[index + 1] = tx_addr_ins[index + 1] + prev_value
                    else:
                        # Otherwise, it is a new address
                        tx_addr_ins = tx_addr_ins + [prev_addr, prev_value]
                    continue
                else:
                    self.logger.warning('Prev tx not found in db!')

            # Add inputs info to make it complete.
            tx_info_complete = tx_info_batch[_tx_hash]
            tx_info_complete['i'] = tx_addr_ins
            tx_info_batch[_tx_hash] = tx_info_complete

        # Write transaction info to db.
        self.put_tx_info_batch(tx_info_batch)
