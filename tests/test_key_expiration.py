# glep63-check -- tests for issues related to key expiration
# (c) 2018 Michał Górny
# Released under the terms of 2-clause BSD license.

import datetime

from glep63.base import (PublicKey, Key, UID, KeyAlgo, Validity,
        KeyWarning, KeyIssue, SubKeyWarning, SubKeyIssue, UIDIssue)

import tests.key_base


class PrimaryKeyNoExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/primary-noexpire.gpg'

    GPG_COLONS = '''
pub:-:4096:1:CFD4B3EC01FB9A51:1533210309:::-:::scSC::::::23::0:
fpr:::::::::8386FCEB4CE07C9FA30F9E71CFD4B3EC01FB9A51:
uid:-::::1533210309::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:14F0813D42225877:1533210363:1564746363:::::s::::::23:
fpr:::::::::693AE5F2C1CCE7CA30FF07F214F0813D42225877:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='CFD4B3EC01FB9A51',
        creation_date=datetime.datetime(2018, 8, 2, 11, 45, 9),
        expiration_date=None,
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='14F0813D42225877',
                creation_date=datetime.datetime(2018, 8, 2, 11, 46, 3),
                expiration_date=datetime.datetime(2019, 8, 2, 11, 46, 3),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 11, 45, 9),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    COMMON_ISSUE = KeyIssue(
        key=KEY,
        machine_desc='expire:none',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [COMMON_ISSUE],
        'glep63-1-rsa2048-ec25519': [COMMON_ISSUE],
        'glep63-1-strict': [COMMON_ISSUE],
        'glep63-2': [COMMON_ISSUE],
        'glep63-2-draft-20180707': [COMMON_ISSUE],
    }


class PrimaryKeyThreeYearExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/primary-3y.gpg'

    GPG_COLONS = '''
pub:-:4096:1:CFD4B3EC01FB9A51:1533210309:1627818785::-:::scSC::::::23::0:
fpr:::::::::8386FCEB4CE07C9FA30F9E71CFD4B3EC01FB9A51:
uid:-::::1533210785::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:14F0813D42225877:1533210363:1564746363:::::s::::::23:
fpr:::::::::693AE5F2C1CCE7CA30FF07F214F0813D42225877:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='CFD4B3EC01FB9A51',
        creation_date=datetime.datetime(2018, 8, 2, 11, 45, 9),
        expiration_date=datetime.datetime(2021, 8, 1, 11, 53, 5),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='14F0813D42225877',
                creation_date=datetime.datetime(2018, 8, 2, 11, 46, 3),
                expiration_date=datetime.datetime(2019, 8, 2, 11, 46, 3),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 11, 53, 5),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    V2_ISSUE = KeyIssue(
        key=KEY,
        machine_desc='expire:long',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [],
        'glep63-1-rsa2048-ec25519': [],
        'glep63-1-strict': [],
        'glep63-2': [V2_ISSUE],
        'glep63-2-draft-20180707': [V2_ISSUE],
    }


class PrimaryKeyTwoYearExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/primary-2y.gpg'

    GPG_COLONS = '''
pub:-:4096:1:CFD4B3EC01FB9A51:1533210309:1596282803::-:::scSC::::::23::0:
fpr:::::::::8386FCEB4CE07C9FA30F9E71CFD4B3EC01FB9A51:
uid:-::::1533210803::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:14F0813D42225877:1533210363:1564746363:::::s::::::23:
fpr:::::::::693AE5F2C1CCE7CA30FF07F214F0813D42225877:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='CFD4B3EC01FB9A51',
        creation_date=datetime.datetime(2018, 8, 2, 11, 45, 9),
        expiration_date=datetime.datetime(2020, 8, 1, 11, 53, 23),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='14F0813D42225877',
                creation_date=datetime.datetime(2018, 8, 2, 11, 46, 3),
                expiration_date=datetime.datetime(2019, 8, 2, 11, 46, 3),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 11, 53, 23),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [],
        'glep63-1-rsa2048-ec25519': [],
        'glep63-1-strict': [],
        'glep63-2': [],
        'glep63-2-draft-20180707': [],
    }


class PrimaryKeyOneWeekExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/primary-1w.gpg'

    GPG_COLONS = '''
pub:-:4096:1:CFD4B3EC01FB9A51:1533210309:1533815624::-:::scSC::::::23::0:
fpr:::::::::8386FCEB4CE07C9FA30F9E71CFD4B3EC01FB9A51:
uid:-::::1533210824::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:14F0813D42225877:1533210363:1564746363:::::s::::::23:
fpr:::::::::693AE5F2C1CCE7CA30FF07F214F0813D42225877:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='CFD4B3EC01FB9A51',
        creation_date=datetime.datetime(2018, 8, 2, 11, 45, 9),
        expiration_date=datetime.datetime(2018, 8, 9, 11, 53, 44),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='14F0813D42225877',
                creation_date=datetime.datetime(2018, 8, 2, 11, 46, 3),
                expiration_date=datetime.datetime(2019, 8, 2, 11, 46, 3),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 11, 53, 44),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    RENEW_WARNING = KeyWarning(
        key=KEY,
        machine_desc='expire:short',
        long_desc='',
    )
    RENEW_ISSUE = KeyIssue(
        key=KEY,
        machine_desc='expire:short',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [RENEW_WARNING],
        'glep63-1-rsa2048-ec25519': [RENEW_WARNING],
        'glep63-1-strict': [RENEW_WARNING],
        'glep63-2': [RENEW_ISSUE],
        'glep63-2-draft-20180707': [RENEW_ISSUE],
    }


class PrimaryKeyFiveYearExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/primary-5y.gpg'

    GPG_COLONS = '''
pub:-:4096:1:CFD4B3EC01FB9A51:1533210309:1690890880::-:::scSC::::::23::0:
fpr:::::::::8386FCEB4CE07C9FA30F9E71CFD4B3EC01FB9A51:
uid:-::::1533210880::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:14F0813D42225877:1533210363:1564746363:::::s::::::23:
fpr:::::::::693AE5F2C1CCE7CA30FF07F214F0813D42225877:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='CFD4B3EC01FB9A51',
        creation_date=datetime.datetime(2018, 8, 2, 11, 45, 9),
        expiration_date=datetime.datetime(2023, 8, 1, 11, 54, 40),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='14F0813D42225877',
                creation_date=datetime.datetime(2018, 8, 2, 11, 46, 3),
                expiration_date=datetime.datetime(2019, 8, 2, 11, 46, 3),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 11, 54, 40),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    V1_ISSUE = KeyWarning(
        key=KEY,
        machine_desc='expire:long',
        long_desc='',
    )
    V2_ISSUE = KeyIssue(
        key=KEY,
        machine_desc='expire:long',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [V1_ISSUE],
        'glep63-1-rsa2048-ec25519': [V1_ISSUE],
        'glep63-1-strict': [V1_ISSUE],
        'glep63-2': [V2_ISSUE],
        'glep63-2-draft-20180707': [V2_ISSUE],
    }


class PrimaryKeySixYearExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/primary-6y.gpg'

    GPG_COLONS = '''
pub:-:4096:1:CFD4B3EC01FB9A51:1533210309:1722426894::-:::scSC::::::23::0:
fpr:::::::::8386FCEB4CE07C9FA30F9E71CFD4B3EC01FB9A51:
uid:-::::1533210894::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:14F0813D42225877:1533210363:1564746363:::::s::::::23:
fpr:::::::::693AE5F2C1CCE7CA30FF07F214F0813D42225877:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='CFD4B3EC01FB9A51',
        creation_date=datetime.datetime(2018, 8, 2, 11, 45, 9),
        expiration_date=datetime.datetime(2024, 7, 31, 11, 54, 54),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='14F0813D42225877',
                creation_date=datetime.datetime(2018, 8, 2, 11, 46, 3),
                expiration_date=datetime.datetime(2019, 8, 2, 11, 46, 3),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 11, 54, 54),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    COMMON_ISSUE = KeyIssue(
        key=KEY,
        machine_desc='expire:long',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [COMMON_ISSUE],
        'glep63-1-rsa2048-ec25519': [COMMON_ISSUE],
        'glep63-1-strict': [COMMON_ISSUE],
        'glep63-2': [COMMON_ISSUE],
        'glep63-2-draft-20180707': [COMMON_ISSUE],
    }


class SubKeyNoExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/subkey-noexpire.gpg'

    GPG_COLONS = '''
pub:-:4096:1:CFD4B3EC01FB9A51:1533210309:1596283281::-:::scSC::::::23::0:
fpr:::::::::8386FCEB4CE07C9FA30F9E71CFD4B3EC01FB9A51:
uid:-::::1533211281::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:14F0813D42225877:1533210363::::::s::::::23:
fpr:::::::::693AE5F2C1CCE7CA30FF07F214F0813D42225877:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='CFD4B3EC01FB9A51',
        creation_date=datetime.datetime(2018, 8, 2, 11, 45, 9),
        expiration_date=datetime.datetime(2020, 8, 1, 12, 1, 21),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='14F0813D42225877',
                creation_date=datetime.datetime(2018, 8, 2, 11, 46, 3),
                expiration_date=None,
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 12, 1, 21),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    COMMON_ISSUE = SubKeyIssue(
        key=KEY,
        subkey=KEY.subkeys[0],
        machine_desc='expire:none',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [COMMON_ISSUE],
        'glep63-1-rsa2048-ec25519': [COMMON_ISSUE],
        'glep63-1-strict': [COMMON_ISSUE],
        'glep63-2': [COMMON_ISSUE],
        'glep63-2-draft-20180707': [COMMON_ISSUE],
    }


class SubKeySixYearExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/subkey-6y.gpg'

    GPG_COLONS = '''
pub:-:4096:1:CFD4B3EC01FB9A51:1533210309:1596283281::-:::scSC::::::23::0:
fpr:::::::::8386FCEB4CE07C9FA30F9E71CFD4B3EC01FB9A51:
uid:-::::1533211281::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:14F0813D42225877:1533210363:1722427329:::::s::::::23:
fpr:::::::::693AE5F2C1CCE7CA30FF07F214F0813D42225877:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='CFD4B3EC01FB9A51',
        creation_date=datetime.datetime(2018, 8, 2, 11, 45, 9),
        expiration_date=datetime.datetime(2020, 8, 1, 12, 1, 21),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='14F0813D42225877',
                creation_date=datetime.datetime(2018, 8, 2, 11, 46, 3),
                expiration_date=datetime.datetime(2024, 7, 31, 12, 2, 9),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 12, 1, 21),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    COMMON_ISSUE = SubKeyIssue(
        key=KEY,
        subkey=KEY.subkeys[0],
        machine_desc='expire:long',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [COMMON_ISSUE],
        'glep63-1-rsa2048-ec25519': [COMMON_ISSUE],
        'glep63-1-strict': [COMMON_ISSUE],
        'glep63-2': [COMMON_ISSUE],
        'glep63-2-draft-20180707': [COMMON_ISSUE],
    }


class SubKeyFiveYearExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/subkey-5y.gpg'

    GPG_COLONS = '''
pub:-:4096:1:CFD4B3EC01FB9A51:1533210309:1596283281::-:::scSC::::::23::0:
fpr:::::::::8386FCEB4CE07C9FA30F9E71CFD4B3EC01FB9A51:
uid:-::::1533211281::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:14F0813D42225877:1533210363:1690891344:::::s::::::23:
fpr:::::::::693AE5F2C1CCE7CA30FF07F214F0813D42225877:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='CFD4B3EC01FB9A51',
        creation_date=datetime.datetime(2018, 8, 2, 11, 45, 9),
        expiration_date=datetime.datetime(2020, 8, 1, 12, 1, 21),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='14F0813D42225877',
                creation_date=datetime.datetime(2018, 8, 2, 11, 46, 3),
                expiration_date=datetime.datetime(2023, 8, 1, 12, 2, 24),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 12, 1, 21),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    V1_ISSUE = SubKeyWarning(
        key=KEY,
        subkey=KEY.subkeys[0],
        machine_desc='expire:long',
        long_desc='',
    )

    V2_ISSUE = SubKeyIssue(
        key=KEY,
        subkey=KEY.subkeys[0],
        machine_desc='expire:long',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [V1_ISSUE],
        'glep63-1-rsa2048-ec25519': [V1_ISSUE],
        'glep63-1-strict': [V1_ISSUE],
        'glep63-2': [V2_ISSUE],
        'glep63-2-draft-20180707': [V2_ISSUE],
    }


class SubKeyTwoYearExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/subkey-2y.gpg'

    GPG_COLONS = '''
pub:-:4096:1:CFD4B3EC01FB9A51:1533210309:1596283281::-:::scSC::::::23::0:
fpr:::::::::8386FCEB4CE07C9FA30F9E71CFD4B3EC01FB9A51:
uid:-::::1533211281::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:14F0813D42225877:1533210363:1596283376:::::s::::::23:
fpr:::::::::693AE5F2C1CCE7CA30FF07F214F0813D42225877:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='CFD4B3EC01FB9A51',
        creation_date=datetime.datetime(2018, 8, 2, 11, 45, 9),
        expiration_date=datetime.datetime(2020, 8, 1, 12, 1, 21),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='14F0813D42225877',
                creation_date=datetime.datetime(2018, 8, 2, 11, 46, 3),
                expiration_date=datetime.datetime(2020, 8, 1, 12, 2, 56),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 12, 1, 21),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    V1_ISSUE = SubKeyWarning(
        key=KEY,
        subkey=KEY.subkeys[0],
        machine_desc='expire:long',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [V1_ISSUE],
        'glep63-1-rsa2048-ec25519': [V1_ISSUE],
        'glep63-1-strict': [V1_ISSUE],
        'glep63-2': [],
        'glep63-2-draft-20180707': [],
    }


class SubKeyOneYearExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/subkey-1y.gpg'

    GPG_COLONS = '''
pub:-:4096:1:CFD4B3EC01FB9A51:1533210309:1596283281::-:::scSC::::::23::0:
fpr:::::::::8386FCEB4CE07C9FA30F9E71CFD4B3EC01FB9A51:
uid:-::::1533211281::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:14F0813D42225877:1533210363:1564747387:::::s::::::23:
fpr:::::::::693AE5F2C1CCE7CA30FF07F214F0813D42225877:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='CFD4B3EC01FB9A51',
        creation_date=datetime.datetime(2018, 8, 2, 11, 45, 9),
        expiration_date=datetime.datetime(2020, 8, 1, 12, 1, 21),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='14F0813D42225877',
                creation_date=datetime.datetime(2018, 8, 2, 11, 46, 3),
                expiration_date=datetime.datetime(2019, 8, 2, 12, 3, 7),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 12, 1, 21),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [],
        'glep63-1-rsa2048-ec25519': [],
        'glep63-1-strict': [],
        'glep63-2': [],
        'glep63-2-draft-20180707': [],
    }


class SubKeyOneWeekExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/subkey-1w.gpg'

    GPG_COLONS = '''
pub:-:4096:1:CFD4B3EC01FB9A51:1533210309:1596283281::-:::scSC::::::23::0:
fpr:::::::::8386FCEB4CE07C9FA30F9E71CFD4B3EC01FB9A51:
uid:-::::1533211281::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:14F0813D42225877:1533210363:1533816201:::::s::::::23:
fpr:::::::::693AE5F2C1CCE7CA30FF07F214F0813D42225877:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='CFD4B3EC01FB9A51',
        creation_date=datetime.datetime(2018, 8, 2, 11, 45, 9),
        expiration_date=datetime.datetime(2020, 8, 1, 12, 1, 21),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='14F0813D42225877',
                creation_date=datetime.datetime(2018, 8, 2, 11, 46, 3),
                expiration_date=datetime.datetime(2018, 8, 9, 12, 3, 21),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 12, 1, 21),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    COMMON_ISSUE = SubKeyWarning(
        key=KEY,
        subkey=KEY.subkeys[0],
        machine_desc='expire:short',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [COMMON_ISSUE],
        'glep63-1-rsa2048-ec25519': [COMMON_ISSUE],
        'glep63-1-strict': [COMMON_ISSUE],
        'glep63-2': [COMMON_ISSUE],
        'glep63-2-draft-20180707': [COMMON_ISSUE],
    }
