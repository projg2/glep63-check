# glep63-check -- tests for issues related to key algos
# (c) 2018 Michał Górny
# Released under the terms of 2-clause BSD license.

import datetime

from glep63.base import (PublicKey, Key, UID, KeyAlgo)

import tests.key_base


class RSA4096GoodKey(tests.key_base.BaseKeyTest):
    KEY_FILE = 'rsa4096-good.gpg'

    GPG_COLONS = '''
pub:u:4096:1:1CA702E06E4BCC77:1533197590:1564733590::u:::scSC::::::23::0:
fpr:::::::::76D807795BF5E849A5577D631CA702E06E4BCC77:
uid:u::::1533197590::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:u:4096:1:7D36F079CF0CA133:1533197744:1564733744:::::s::::::23:
fpr:::::::::62D59FE2046463CD65D44A247D36F079CF0CA133:
'''

    KEY = PublicKey(
        validity='u',
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='1CA702E06E4BCC77',
        creation_date=datetime.datetime(2018, 8, 2, 8, 13, 10),
        expiration_date=datetime.datetime(2019, 8, 2, 8, 13, 10),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity='u',
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='7D36F079CF0CA133',
                creation_date=datetime.datetime(2018, 8, 2, 8, 15, 44),
                expiration_date=datetime.datetime(2019, 8, 2, 8, 15, 44),
                key_caps='s', curve=''),
        ],
        uids=[
            UID(
                validity='u',
                creation_date=datetime.datetime(2018, 8, 2, 8, 13, 10),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>'),
        ])

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [],
        'glep63-1-strict': [],
        'glep63-1-rsa2048-ec25519': [],
        'glep63-2-draft-20180707': [],
        'glep63-2': [],
    }
