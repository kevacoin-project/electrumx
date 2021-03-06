# Copyright (c) 2016-2018, Neil Booth
# Copyright (c) 2017, the ElectrumX authors
# Copyright (c) 2021, the Kevacoin Project Core Developers
#
# All rights reserved.
#
# See the file "LICENCE" for information about the copyright
# and warranty status of this software.

'''Key-value by tx id.'''

from aiorpcx import TaskGroup, run_in_thread

import electrumx.lib.util as util
from electrumx.lib.util import pack_be_uint16, unpack_be_uint16_from
from electrumx.lib.hash import hash_to_hex_str, HASHX_LEN


class Keva(object):

    DB_VERSIONS = [0]
    # Only use first 16 bytes of tx hash to save space.
    # The chance of collision is extremely small.
    PARTIAL_TX_HASH = 16

    def __init__(self):
        self.logger = util.class_logger(__name__, self.__class__.__name__)
        self.db_version = max(self.DB_VERSIONS)
        self.db = None

    def open_db(self, db_class, for_sync):
        self.db = db_class('keva', for_sync)

    def close_db(self):
        if self.db:
            self.db.close()
            self.db = None

    def put_keva_script(self, tx_hash, keva_script):
        self.db.put(tx_hash[0:self.PARTIAL_TX_HASH], keva_script)

    def is_banned(self, keva_script):
        return keva_script[1] == 0xff and keva_script[2] == 0xff and keva_script[3] == 0xff

    def put_keva_ban_tx_sync(self, tx_hash, reason=0):
        keva_script = self.db.get(tx_hash[0:self.PARTIAL_TX_HASH])
        if (not keva_script) or self.is_banned(keva_script):
            return

        ban_prefix = bytes([(reason & 0xff), 0xff, 0xff, 0xff])
        self.db.put(tx_hash[0:self.PARTIAL_TX_HASH], ban_prefix + keva_script)

    async def put_keva_ban_tx(self, tx_hash, reason=0):
        return await run_in_thread(self.put_keva_ban_tx_sync, tx_hash, reason)

    def remove_keva_ban_tx_sync(self, tx_hash):
        keva_script = self.db.get(tx_hash[0:self.PARTIAL_TX_HASH])
        if (not keva_script) or (not self.is_banned(keva_script)):
            return

        self.db.put(tx_hash[0:self.PARTIAL_TX_HASH], keva_script[4:])

    async def remove_keva_ban_tx(self, tx_hash):
        return await run_in_thread(self.remove_keva_ban_tx_sync, tx_hash)

    def put_keva_script_batch(self, keva_script_batch):
        with self.db.write_batch() as batch:
            for tx_hash, keva_script in keva_script_batch:
                batch.put(tx_hash[0:self.PARTIAL_TX_HASH], keva_script)

    async def get_keva_script(self, tx_hash):
        return await run_in_thread(self.db.get, tx_hash[0:self.PARTIAL_TX_HASH])
