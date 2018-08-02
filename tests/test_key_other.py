# glep63-check -- tests for other key issues
# (c) 2018 Michał Górny
# Released under the terms of 2-clause BSD license.

import datetime

from glep63.base import (PublicKey, Key, UID, KeyAlgo, Validity,
        KeyWarning, KeyIssue, SubKeyWarning, SubKeyIssue, UIDIssue)

import tests.key_base


class ExpiredKeyTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'other/expired-key.gpg'

    GPG_COLONS = '''
pub:e:4096:1:DB44A8BC23B67AF4:946681246:946767646::-:::sc::::::23::0:
fpr:::::::::723AADD29743D410B5CAD9CEDB44A8BC23B67AF4:
uid:e::::946681246::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:e:4096:1:D4E7C940C84DD0DA:946681260:1545865383:::::s::::::23:
fpr:::::::::A23A271C81A008C088BB0A2CD4E7C940C84DD0DA:
'''

    KEY = PublicKey(
        validity=Validity.EXPIRED,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='DB44A8BC23B67AF4',
        creation_date=datetime.datetime(1999, 12, 31, 23, 0, 46),
        expiration_date=datetime.datetime(2000, 1, 1, 23, 0, 46),
        key_caps='sc',
        curve='',
        subkeys=[
            Key(
                validity=Validity.EXPIRED,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='D4E7C940C84DD0DA',
                creation_date=datetime.datetime(1999, 12, 31, 23, 1),
                expiration_date=datetime.datetime(2018, 12, 26, 23, 3, 3),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity='e',
                creation_date=datetime.datetime(1999, 12, 31, 23, 0, 46),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    COMMON_ISSUE = KeyIssue(
        key=KEY,
        machine_desc='validity:expired',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [COMMON_ISSUE],
        'glep63-1-rsa2048-ec25519': [COMMON_ISSUE],
        'glep63-1-strict': [COMMON_ISSUE],
        'glep63-2': [COMMON_ISSUE],
        'glep63-2-draft-20180707': [COMMON_ISSUE],
    }


class RevokedKeyTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'other/revoked-key.gpg'

    GPG_COLONS = '''
pub:r:4096:1:CD407D01E7D00880:946682289:978218289::-:::sc::::::23::0:
fpr:::::::::F0769AC027B2117ECFAB7F1BCD407D01E7D00880:
uid:r::::946682289::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:r:4096:1:F9FDA2910B574DA4:946682301:978218301:::::s::::::23:
fpr:::::::::A76730D5141B96EFAA7B3E4AF9FDA2910B574DA4:
'''

    KEY = PublicKey(
        validity=Validity.REVOKED,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='CD407D01E7D00880',
        creation_date=datetime.datetime(1999, 12, 31, 23, 18, 9),
        expiration_date=datetime.datetime(2000, 12, 30, 23, 18, 9),
        key_caps='sc',
        curve='',
        subkeys=[
            Key(
                validity=Validity.REVOKED,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='F9FDA2910B574DA4',
                creation_date=datetime.datetime(1999, 12, 31, 23, 18, 21),
                expiration_date=datetime.datetime(2000, 12, 30, 23, 18, 21),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity='r',
                creation_date=datetime.datetime(1999, 12, 31, 23, 18, 9),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    COMMON_ISSUE = KeyIssue(
        key=KEY,
        machine_desc='validity:revoked',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [COMMON_ISSUE],
        'glep63-1-rsa2048-ec25519': [COMMON_ISSUE],
        'glep63-1-strict': [COMMON_ISSUE],
        'glep63-2': [COMMON_ISSUE],
        'glep63-2-draft-20180707': [COMMON_ISSUE],
    }
