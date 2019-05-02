# glep63-check -- tests for issues related to key expiration
# (c) 2018-2019 Michał Górny
# Released under the terms of 2-clause BSD license.

import datetime

from glep63.base import (PublicKey, Key, UID, KeyAlgo, Validity,
        KeyWarning, KeyIssue, SubKeyWarning, SubKeyIssue)

import tests.key_base


class PrimaryKeyNoExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/primary-noexpire.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247201::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:3F911DBFC4B51F74:1533247201:1564783201:::::s::::::23:
fpr:::::::::26BF2B75CB42D5803C615AF43F911DBFC4B51F74:
sub:-:4096:1:44C9C2CFA6974493:1533247201:1564783201:::::e::::::23:
fpr:::::::::CF8439AF79B439E0D9D7C99B44C9C2CFA6974493:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=None,
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='3F911DBFC4B51F74',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 1),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='44C9C2CFA6974493',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 1),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:none',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:none',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:none',
                long_desc='',
            ),
        ],
        'glep63-2': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:none',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:none',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:none',
                long_desc='',
            ),
        ],
    }


class PrimaryKeyThreeYearExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/primary-3y.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1627855202::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247202::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:3F911DBFC4B51F74:1533247201:1564783201:::::s::::::23:
fpr:::::::::26BF2B75CB42D5803C615AF43F911DBFC4B51F74:
sub:-:4096:1:44C9C2CFA6974493:1533247201:1564783201:::::e::::::23:
fpr:::::::::CF8439AF79B439E0D9D7C99B44C9C2CFA6974493:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2021, 8, 1, 22, 0, 2),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='3F911DBFC4B51F74',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 1),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='44C9C2CFA6974493',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 1),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 2),
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
        'glep63-2': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
    }


class PrimaryKeyTwoYearExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/primary-2y.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1596319203::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247203::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:3F911DBFC4B51F74:1533247201:1564783201:::::s::::::23:
fpr:::::::::26BF2B75CB42D5803C615AF43F911DBFC4B51F74:
sub:-:4096:1:44C9C2CFA6974493:1533247201:1564783201:::::e::::::23:
fpr:::::::::CF8439AF79B439E0D9D7C99B44C9C2CFA6974493:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2020, 8, 1, 22, 0, 3),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='3F911DBFC4B51F74',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 1),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='44C9C2CFA6974493',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 1),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 3),
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
        'glep63-2.1': [],
    }


class PrimaryKeyOneWeekExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/primary-1w.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1533852004::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247204::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:3F911DBFC4B51F74:1533247201:1564783201:::::s::::::23:
fpr:::::::::26BF2B75CB42D5803C615AF43F911DBFC4B51F74:
sub:-:4096:1:44C9C2CFA6974493:1533247201:1564783201:::::e::::::23:
fpr:::::::::CF8439AF79B439E0D9D7C99B44C9C2CFA6974493:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2018, 8, 9, 22, 0, 4),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='3F911DBFC4B51F74',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 1),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='44C9C2CFA6974493',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 1),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 4),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [
            KeyWarning(
                key=KEY,
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            KeyWarning(
                key=KEY,
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            KeyWarning(
                key=KEY,
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
        'glep63-2': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
    }


class PrimaryKeyFiveYearExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/primary-5y.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1690927205::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247205::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:3F911DBFC4B51F74:1533247201:1564783201:::::s::::::23:
fpr:::::::::26BF2B75CB42D5803C615AF43F911DBFC4B51F74:
sub:-:4096:1:44C9C2CFA6974493:1533247201:1564783201:::::e::::::23:
fpr:::::::::CF8439AF79B439E0D9D7C99B44C9C2CFA6974493:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2023, 8, 1, 22, 0, 5),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='3F911DBFC4B51F74',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 1),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='44C9C2CFA6974493',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 1),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 5),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [
            KeyWarning(
                key=KEY,
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            KeyWarning(
                key=KEY,
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            KeyWarning(
                key=KEY,
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-2': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
    }


class PrimaryKeySixYearExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/primary-6y.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1722463206::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247206::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:3F911DBFC4B51F74:1533247201:1564783201:::::s::::::23:
fpr:::::::::26BF2B75CB42D5803C615AF43F911DBFC4B51F74:
sub:-:4096:1:44C9C2CFA6974493:1533247201:1564783201:::::e::::::23:
fpr:::::::::CF8439AF79B439E0D9D7C99B44C9C2CFA6974493:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2024, 7, 31, 22, 0, 6),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='3F911DBFC4B51F74',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 1),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='44C9C2CFA6974493',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 1),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 6),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-2': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
    }


class SubKeyNoExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/subkey-noexpire.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783207::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247207::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:3F911DBFC4B51F74:1533247201::::::s::::::23:
fpr:::::::::26BF2B75CB42D5803C615AF43F911DBFC4B51F74:
sub:-:4096:1:44C9C2CFA6974493:1533247201::::::e::::::23:
fpr:::::::::CF8439AF79B439E0D9D7C99B44C9C2CFA6974493:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 7),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='3F911DBFC4B51F74',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=None,
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='44C9C2CFA6974493',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=None,
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 7),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:none',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:none',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:none',
                long_desc='',
            ),
        ],
        'glep63-2': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:none',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:none',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:none',
                long_desc='',
            ),
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[1],
                machine_desc='expire:none',
                long_desc='',
            ),
        ],
    }


class SubKeySixYearExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/subkey-6y.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783207::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247207::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:3F911DBFC4B51F74:1533247201:1722463208:::::s::::::23:
fpr:::::::::26BF2B75CB42D5803C615AF43F911DBFC4B51F74:
sub:-:4096:1:44C9C2CFA6974493:1533247201:1722463208:::::e::::::23:
fpr:::::::::CF8439AF79B439E0D9D7C99B44C9C2CFA6974493:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 7),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='3F911DBFC4B51F74',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2024, 7, 31, 22, 0, 8),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='44C9C2CFA6974493',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2024, 7, 31, 22, 0, 8),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 7),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-2': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:long',
                long_desc='',
            ),
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[1],
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
    }


class SubKeyFiveYearExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/subkey-5y.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783207::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247207::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:3F911DBFC4B51F74:1533247201:1690927209:::::s::::::23:
fpr:::::::::26BF2B75CB42D5803C615AF43F911DBFC4B51F74:
sub:-:4096:1:44C9C2CFA6974493:1533247201:1690927209:::::e::::::23:
fpr:::::::::CF8439AF79B439E0D9D7C99B44C9C2CFA6974493:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 7),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='3F911DBFC4B51F74',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2023, 8, 1, 22, 0, 9),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='44C9C2CFA6974493',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2023, 8, 1, 22, 0, 9),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 7),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-2': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:long',
                long_desc='',
            ),
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[1],
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
    }


class SubKeyTwoYearExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/subkey-2y.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783207::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247207::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:3F911DBFC4B51F74:1533247201:1596319210:::::s::::::23:
fpr:::::::::26BF2B75CB42D5803C615AF43F911DBFC4B51F74:
sub:-:4096:1:44C9C2CFA6974493:1533247201:1596319210:::::e::::::23:
fpr:::::::::CF8439AF79B439E0D9D7C99B44C9C2CFA6974493:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 7),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='3F911DBFC4B51F74',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2020, 8, 1, 22, 0, 10),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='44C9C2CFA6974493',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2020, 8, 1, 22, 0, 10),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 7),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:long',
                long_desc='',
            ),
        ],
        'glep63-2': [],
        'glep63-2-draft-20180707': [],
        'glep63-2.1': [],
    }


class SubKeyOneWeekExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/subkey-1w.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783207::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247207::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:3F911DBFC4B51F74:1533247201:1533852011:::::s::::::23:
fpr:::::::::26BF2B75CB42D5803C615AF43F911DBFC4B51F74:
sub:-:4096:1:44C9C2CFA6974493:1533247201:1533852011:::::e::::::23:
fpr:::::::::CF8439AF79B439E0D9D7C99B44C9C2CFA6974493:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 7),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='3F911DBFC4B51F74',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2018, 8, 9, 22, 0, 11),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='44C9C2CFA6974493',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2018, 8, 9, 22, 0, 11),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 7),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
        'glep63-2': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:short',
                long_desc='',
            ),
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[1],
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
    }


class TwoSubKeysExpirationTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'expiration/two-subkeys-1w-1y.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783207::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247207::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:3F911DBFC4B51F74:1533247201:1533852011:::::s::::::23:
fpr:::::::::26BF2B75CB42D5803C615AF43F911DBFC4B51F74:
sub:-:4096:1:44C9C2CFA6974493:1533247201:1533852011:::::e::::::23:
fpr:::::::::CF8439AF79B439E0D9D7C99B44C9C2CFA6974493:
sub:-:4096:1:88580872B51C08B9:1533247212:1564783212:::::s::::::23:
fpr:::::::::3D36B68F75BA09167B32CF0C88580872B51C08B9:
sub:-:4096:1:2D927DAC6A85C6BD:1533247212:1564783212:::::e::::::23:
fpr:::::::::F216FC6F6C4EC3AD4DE4A4AF2D927DAC6A85C6BD:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 7),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='3F911DBFC4B51F74',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2018, 8, 9, 22, 0, 11),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='44C9C2CFA6974493',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 1),
                expiration_date=datetime.datetime(2018, 8, 9, 22, 0, 11),
                key_caps='e',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='88580872B51C08B9',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 12),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 12),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='2D927DAC6A85C6BD',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 12),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 12),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 7),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
        'glep63-2': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='expire:short',
                long_desc='',
            ),
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[1],
                machine_desc='expire:short',
                long_desc='',
            ),
        ],
    }
