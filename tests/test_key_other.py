# glep63-check -- tests for other key issues
# (c) 2018-2019 Michał Górny
# Released under the terms of 2-clause BSD license.

import datetime

from glep63.base import (PublicKey, Key, UID, KeyAlgo, Validity,
        KeyWarning, KeyIssue, SubKeyWarning)

import tests.key_base


class ExpiredKeyTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'other/expired-key.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
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
                validity=Validity.EXPIRED,
                creation_date=datetime.datetime(1999, 12, 31, 23, 0, 46),
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
                machine_desc='validity:expired',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            KeyIssue(
                key=KEY,
                machine_desc='validity:expired',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            KeyIssue(
                key=KEY,
                machine_desc='validity:expired',
                long_desc='',
            ),
        ],
        'glep63-2': [
            KeyIssue(
                key=KEY,
                machine_desc='validity:expired',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            KeyIssue(
                key=KEY,
                machine_desc='validity:expired',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='validity:expired',
                long_desc='',
            ),
        ],
    }


class RevokedKeyTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'other/revoked-key.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
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
                validity=Validity.REVOKED,
                creation_date=datetime.datetime(1999, 12, 31, 23, 18, 9),
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
                machine_desc='validity:revoked',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            KeyIssue(
                key=KEY,
                machine_desc='validity:revoked',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            KeyIssue(
                key=KEY,
                machine_desc='validity:revoked',
                long_desc='',
            ),
        ],
        'glep63-2': [
            KeyIssue(
                key=KEY,
                machine_desc='validity:revoked',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            KeyIssue(
                key=KEY,
                machine_desc='validity:revoked',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='validity:revoked',
                long_desc='',
            ),
        ],
    }


class NoSigningSubKeyTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'other/no-signing-subkey.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783207::-:::scESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247212::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
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
        key_caps='scESC',
        curve='',
        subkeys=[
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
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 12),
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
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
        'glep63-2': [
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
    }


class MultipurposeSubKeyTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'other/multipurpose-subkey.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783207::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247213::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:2D927DAC6A85C6BD:1533247212:1564783212:::::es::::::23:
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
                keyid='2D927DAC6A85C6BD',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 12),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 12),
                key_caps='es',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 13),
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
                machine_desc='subkey:multipurpose',
                long_desc='',
            ),
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='subkey:multipurpose',
                long_desc='',
            ),
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='subkey:multipurpose',
                long_desc='',
            ),
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
        'glep63-2': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='subkey:multipurpose',
                long_desc='',
            ),
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='subkey:multipurpose',
                long_desc='',
            ),
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='subkey:multipurpose',
                long_desc='',
            ),
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:e',
                long_desc='',
            ),
        ],
    }


class NoEncryptionSubKeyTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'other/no-encryption-subkey.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783207::-:::cSC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247213::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:2D927DAC6A85C6BD:1533247212:1564783212:::::s::::::23:
fpr:::::::::F216FC6F6C4EC3AD4DE4A4AF2D927DAC6A85C6BD:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 7),
        key_caps='cSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='2D927DAC6A85C6BD',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 12),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 12),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 13),
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
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:e',
                long_desc='',
            ),
        ],
    }


class RevokedGentooUIDTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'other/revoked-gentoo-uid.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783207::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247215::5D26637AF3E9C4C07D3971B0BFC9D8AB2C3F8CA3::GLEP63 test key <nobody@example.com>::::::::::0:
uid:r::::::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:2D927DAC6A85C6BD:1533247212:1564783212:::::s::::::23:
fpr:::::::::F216FC6F6C4EC3AD4DE4A4AF2D927DAC6A85C6BD:
sub:-:4096:1:D1DE5B31DBAB4E09:1533247215:1564783215:::::e::::::23:
fpr:::::::::C40C2A33B028C24C6FA21BF0D1DE5B31DBAB4E09:
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
                keyid='2D927DAC6A85C6BD',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 12),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 12),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='D1DE5B31DBAB4E09',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 15),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 15),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 15),
                expiration_date=None,
                uid_hash='5D26637AF3E9C4C07D3971B0BFC9D8AB2C3F8CA3',
                user_id='GLEP63 test key <nobody@example.com>',
            ),
            UID(
                validity=Validity.REVOKED,
                creation_date=None,
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
                machine_desc='uid:nogentoo',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            KeyWarning(
                key=KEY,
                machine_desc='uid:nogentoo',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            KeyWarning(
                key=KEY,
                machine_desc='uid:nogentoo',
                long_desc='',
            ),
        ],
        'glep63-2': [
            KeyIssue(
                key=KEY,
                machine_desc='uid:nogentoo',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            KeyWarning(
                key=KEY,
                machine_desc='uid:nogentoo',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='uid:nogentoo',
                long_desc='',
            ),
        ],
    }


class NoGentooUIDTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'other/no-gentoo-uid.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783207::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247215::5D26637AF3E9C4C07D3971B0BFC9D8AB2C3F8CA3::GLEP63 test key <nobody@example.com>::::::::::0:
sub:-:4096:1:2D927DAC6A85C6BD:1533247212:1564783212:::::s::::::23:
fpr:::::::::F216FC6F6C4EC3AD4DE4A4AF2D927DAC6A85C6BD:
sub:-:4096:1:D1DE5B31DBAB4E09:1533247215:1564783215:::::e::::::23:
fpr:::::::::C40C2A33B028C24C6FA21BF0D1DE5B31DBAB4E09:
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
                keyid='2D927DAC6A85C6BD',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 12),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 12),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='D1DE5B31DBAB4E09',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 15),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 15),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 15),
                expiration_date=None,
                uid_hash='5D26637AF3E9C4C07D3971B0BFC9D8AB2C3F8CA3',
                user_id='GLEP63 test key <nobody@example.com>',
            ),
        ],
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [
            KeyWarning(
                key=KEY,
                machine_desc='uid:nogentoo',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            KeyWarning(
                key=KEY,
                machine_desc='uid:nogentoo',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            KeyWarning(
                key=KEY,
                machine_desc='uid:nogentoo',
                long_desc='',
            ),
        ],
        'glep63-2': [
            KeyIssue(
                key=KEY,
                machine_desc='uid:nogentoo',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            KeyWarning(
                key=KEY,
                machine_desc='uid:nogentoo',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='uid:nogentoo',
                long_desc='',
            ),
        ],
    }


class RevokedSubKeyOnlyTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'other/revoked-subkey-only.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783207::-:::cC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247213::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:r:4096:1:2D927DAC6A85C6BD:1533247212:1564783212:::::s::::::23:
fpr:::::::::F216FC6F6C4EC3AD4DE4A4AF2D927DAC6A85C6BD:
sub:r:4096:1:D1DE5B31DBAB4E09:1533247215:1564783215:::::e::::::23:
fpr:::::::::C40C2A33B028C24C6FA21BF0D1DE5B31DBAB4E09:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 7),
        key_caps='cC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.REVOKED,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='2D927DAC6A85C6BD',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 12),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 12),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.REVOKED,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='D1DE5B31DBAB4E09',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 15),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 15),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 13),
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
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
        'glep63-2': [
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:s',
                long_desc='',
            ),
            KeyIssue(
                key=KEY,
                machine_desc='subkey:none:e',
                long_desc='',
            ),
        ],
    }


class RevokedShortSubKeyTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'other/revoked-short-subkey.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783207::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247213::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:2D927DAC6A85C6BD:1533247212:1564783212:::::s::::::23:
fpr:::::::::F216FC6F6C4EC3AD4DE4A4AF2D927DAC6A85C6BD:
sub:-:4096:1:D1DE5B31DBAB4E09:1533247215:1564783215:::::e::::::23:
fpr:::::::::C40C2A33B028C24C6FA21BF0D1DE5B31DBAB4E09:
sub:r:1024:1:B3486BCC2DC48389:1533247215:1564783215:::::s:::::::
fpr:::::::::DEFA19BB1BEC81CD0E8B2B63B3486BCC2DC48389:
sub:r:1024:1:31EF1F504A39CC46:1533247215:1564783215:::::e:::::::
fpr:::::::::4BDEA4604CAABF8C158B66F731EF1F504A39CC46:
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
                keyid='2D927DAC6A85C6BD',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 12),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 12),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='D1DE5B31DBAB4E09',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 15),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 15),
                key_caps='e',
                curve='',
            ),
            Key(
                validity=Validity.REVOKED,
                key_length=1024,
                key_algo=KeyAlgo.RSA,
                keyid='B3486BCC2DC48389',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 15),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 15),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.REVOKED,
                key_length=1024,
                key_algo=KeyAlgo.RSA,
                keyid='31EF1F504A39CC46',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 15),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0, 15),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0, 13),
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
