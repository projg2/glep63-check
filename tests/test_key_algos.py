# glep63-check -- tests for issues related to key algos
# (c) 2018-2019 Michał Górny
# Released under the terms of 2-clause BSD license.

import datetime
import unittest

from glep63.base import (PublicKey, Key, UID, KeyAlgo, Validity,
        KeyWarning, KeyIssue, SubKeyWarning, SubKeyIssue)

import tests.key_base


class RSA4096GoodKeyTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/rsa4096-good.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783200::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247200::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:805B6A269267F80B:1533247200:1564783200:::::s::::::23:
fpr:::::::::1E90F21FE9305E81F74A1493805B6A269267F80B:
sub:-:4096:1:7A9ABB819370914C:1533247200:1564783200:::::e::::::23:
fpr:::::::::229609A52A4F11CF6745835A7A9ABB819370914C:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='805B6A269267F80B',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='7A9ABB819370914C',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
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


class RSA2048GoodKeyTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/rsa2048-good.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:2048:1:A25BE39105C7ECE2:1533247200:1564783200::-:::cESC::::::23::0:
fpr:::::::::1242E5978CF42CA392240E7DA25BE39105C7ECE2:
uid:-::::1533247200::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:2048:1:A59FFA2F61388492:1533247200:1564783200:::::s::::::23:
fpr:::::::::4D308CDC25B1CD9881E3557AA59FFA2F61388492:
sub:-:2048:1:D18FCB9CA5CF829A:1533247200:1564783200:::::e::::::23:
fpr:::::::::432C3A7F86B54FCA365B20E1D18FCB9CA5CF829A:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=2048,
        key_algo=KeyAlgo.RSA,
        keyid='A25BE39105C7ECE2',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=2048,
                key_algo=KeyAlgo.RSA,
                keyid='A59FFA2F61388492',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=2048,
                key_algo=KeyAlgo.RSA,
                keyid='D18FCB9CA5CF829A',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [],
        'glep63-1-rsa2048-ec25519': [],
        'glep63-1-strict': [
            KeyWarning(
                key=KEY,
                machine_desc='algo:rsa:short',
                long_desc='',
            ),
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='algo:rsa:short',
                long_desc='',
            ),
        ],
        'glep63-2': [],
        'glep63-2-draft-20180707': [],
        'glep63-2.1': [],
    }


class RSA4096Sub2048Test(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/rsa4096-2048.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783200::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247200::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:2048:1:0CEF810E92F421D0:1533247200:1564783200:::::s::::::23:
fpr:::::::::4E0FF571017E227FB3D3BF990CEF810E92F421D0:
sub:-:2048:1:23409257D078B438:1533247200:1564783200:::::e::::::23:
fpr:::::::::8B50D9779B2729186AFC2AEA23409257D078B438:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=2048,
                key_algo=KeyAlgo.RSA,
                keyid='0CEF810E92F421D0',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=2048,
                key_algo=KeyAlgo.RSA,
                keyid='23409257D078B438',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [],
        'glep63-1-rsa2048-ec25519': [],
        'glep63-1-strict': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='algo:rsa:short',
                long_desc='',
            ),
        ],
        'glep63-2': [],
        'glep63-2-draft-20180707': [],
        'glep63-2.1': [],
    }


class RSA1024Sub4096Test(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/rsa1024-4096.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:1024:1:8968FF836C750226:1533247200:1564783200::-:::cESC::::::::0:
fpr:::::::::580D5B1A25E0FCEE17A2D8C58968FF836C750226:
uid:-::::1533247200::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:2136B9E77645305A:1533247200:1564783200:::::s::::::23:
fpr:::::::::1AEBF8D6C9BCA3432B3423202136B9E77645305A:
sub:-:4096:1:C0CDDEE90139BC28:1533247200:1564783200:::::e::::::23:
fpr:::::::::A721D7C7D46B53AC1750CC87C0CDDEE90139BC28:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=1024,
        key_algo=KeyAlgo.RSA,
        keyid='8968FF836C750226',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='2136B9E77645305A',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='C0CDDEE90139BC28',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
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
                machine_desc='algo:rsa:tooshort',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:rsa:tooshort',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:rsa:tooshort',
                long_desc='',
            ),
        ],
        'glep63-2': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:rsa:tooshort',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:rsa:tooshort',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:rsa:tooshort',
                long_desc='',
            ),
        ],
    }


class DSA2048RSA4096Test(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/dsa2048-rsa4096.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:2048:17:A3820AC4BFC9EA7B:1533247200:1564783200::-:::cESC::::::23::0:
fpr:::::::::81F356D819C6EF96D7AC1FF5A3820AC4BFC9EA7B:
uid:-::::1533247200::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:5C00416EFBC0C9C4:1533247200:1564783200:::::s::::::23:
fpr:::::::::D15D7611E67E1686FDFD47FE5C00416EFBC0C9C4:
sub:-:4096:1:42D2EC9482C50985:1533247200:1564783200:::::e::::::23:
fpr:::::::::F875F3C4C7DA08C0E8E6D84842D2EC9482C50985:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=2048,
        key_algo=KeyAlgo.DSA,
        keyid='A3820AC4BFC9EA7B',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='5C00416EFBC0C9C4',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='42D2EC9482C50985',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
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
                machine_desc='algo:dsa:discouraged',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            KeyWarning(
                key=KEY,
                machine_desc='algo:dsa:discouraged',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            KeyWarning(
                key=KEY,
                machine_desc='algo:dsa:discouraged',
                long_desc='',
            ),
        ],
        'glep63-2': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:dsa',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:dsa',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:dsa',
                long_desc='',
            ),
        ],
    }


class RSA4096DSA2048Test(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/rsa4096-dsa2048.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:4096:1:0F2446E70C90BD31:1533247200:1564783200::-:::cESC::::::23::0:
fpr:::::::::4D94D1CD1D552073A6579CE70F2446E70C90BD31:
uid:-::::1533247200::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:2048:17:7DFD43CE76C91FFF:1533247200:1564783200:::::s::::::23:
fpr:::::::::04D03D6DE88E41CF9AC7DB957DFD43CE76C91FFF:
sub:-:2048:16:A8147FD627F36D82:1533247200:1564783200:::::e:::::::
fpr:::::::::27802BF224123FE218BE2157A8147FD627F36D82:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='0F2446E70C90BD31',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=2048,
                key_algo=KeyAlgo.DSA,
                keyid='7DFD43CE76C91FFF',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=2048,
                key_algo=KeyAlgo.ELGAMAL,
                keyid='A8147FD627F36D82',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
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
                machine_desc='algo:dsa:discouraged',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='algo:dsa:discouraged',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            SubKeyWarning(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='algo:dsa:discouraged',
                long_desc='',
            ),
        ],
        'glep63-2': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='algo:dsa',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='algo:dsa',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='algo:dsa',
                long_desc='',
            ),
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[1],
                machine_desc='algo:dsa',
                long_desc='',
            ),
        ],
    }


class DSA1024RSA4096Test(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/dsa1024-rsa4096.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:1024:17:DE3C8B783203C4FB:1533247200:1564783200::-:::cESC::::::::0:
fpr:::::::::BA5A6956B39769D03A74BA4BDE3C8B783203C4FB:
uid:-::::1533247200::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:6AC198DBD9833EDF:1533247200:1564783200:::::s::::::23:
fpr:::::::::5BB98DA741B86A20A2AF3F936AC198DBD9833EDF:
sub:-:4096:1:15F2D6D394723D5A:1533247200:1564783200:::::e::::::23:
fpr:::::::::4BCF2912F8CA08721A6F9FE015F2D6D394723D5A:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=1024,
        key_algo=KeyAlgo.DSA,
        keyid='DE3C8B783203C4FB',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
        key_caps='cESC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='6AC198DBD9833EDF',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='s',
                curve='',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='15F2D6D394723D5A',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='e',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
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
                machine_desc='algo:dsa:tooshort',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:dsa:tooshort',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:dsa:tooshort',
                long_desc='',
            ),
        ],
        'glep63-2': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:dsa',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:dsa',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:dsa',
                long_desc='',
            ),
        ],
    }


class ED25519Test(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/ed25519.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:256:22:13447F0775EF5B7F:1533247200:1564783200::-:::cESC:::::ed25519:::0:
fpr:::::::::5A4891EDB747391F18D42EA913447F0775EF5B7F:
uid:-::::1533247200::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:256:22:80D111D2FB1375A7:1533247200:1564783200:::::s:::::ed25519::
fpr:::::::::D0867191FFAEA9EBAF6AF7F880D111D2FB1375A7:
sub:-:256:18:B3F692723809542E:1533247200:1564783200:::::e:::::cv25519::
fpr:::::::::1C9B67F422DEE6C6C557B186B3F692723809542E:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=256,
        key_algo=KeyAlgo.EDDSA,
        keyid='13447F0775EF5B7F',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
        key_caps='cESC',
        curve='ed25519',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=256,
                key_algo=KeyAlgo.EDDSA,
                keyid='80D111D2FB1375A7',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='s',
                curve='ed25519',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=256,
                key_algo=KeyAlgo.ECDH,
                keyid='B3F692723809542E',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='e',
                curve='cv25519',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
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
                machine_desc='algo:ecc',
                long_desc='',
            ),
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='algo:ecc',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [],
        'glep63-1-strict': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:ecc',
                long_desc='',
            ),
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='algo:ecc',
                long_desc='',
            ),
        ],
        'glep63-2': [],
        'glep63-2-draft-20180707': [],
        'glep63-2.1': [],
    }

    def test_integration(self):
        for vl in tests.key_base.get_gnupg_version().splitlines():
            if vl.startswith(b'Pubkey:') and b'EDDSA' in vl:
                break
        else:
            raise unittest.SkipTest('GnuPG does not seem to have EDDSA support')

        super(ED25519Test, self).test_integration()


class NISTP256Test(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/nistp256.gpg'

    GPG_COLONS = '''
tru::1:1556681170:1560354194:3:1:5
pub:-:256:19:19F1BB7773CE59DB:1533247200:1564783200::-:::cESC:::::nistp256:::0:
fpr:::::::::509678D482A4F5DC2B22807B19F1BB7773CE59DB:
uid:-::::1533247200::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:256:19:7ABCAF3DF78656A3:1533247200:1564783200:::::s:::::nistp256::
fpr:::::::::2177230042F2A6A33BDE94477ABCAF3DF78656A3:
sub:-:256:18:9E8253E10FF514B5:1533247200:1564783200:::::e:::::nistp256::
fpr:::::::::5BA1F267C46C783BAD52ECF29E8253E10FF514B5:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=256,
        key_algo=KeyAlgo.ECDSA,
        keyid='19F1BB7773CE59DB',
        creation_date=datetime.datetime(2018, 8, 2, 22, 0),
        expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
        key_caps='cESC',
        curve='nistp256',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=256,
                key_algo=KeyAlgo.ECDSA,
                keyid='7ABCAF3DF78656A3',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='s',
                curve='nistp256',
            ),
            Key(
                validity=Validity.NO_VALUE,
                key_length=256,
                key_algo=KeyAlgo.ECDH,
                keyid='9E8253E10FF514B5',
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
                expiration_date=datetime.datetime(2019, 8, 2, 22, 0),
                key_caps='e',
                curve='nistp256',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 22, 0),
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
                machine_desc='algo:ecc',
                long_desc='',
            ),
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='algo:ecc',
                long_desc='',
            ),
        ],
        'glep63-1-rsa2048-ec25519': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:ecc:invalid',
                long_desc='',
            ),
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='algo:ecc:invalid',
                long_desc='',
            ),
        ],
        'glep63-1-strict': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:ecc',
                long_desc='',
            ),
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='algo:ecc',
                long_desc='',
            ),
        ],
        'glep63-2': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:ecc:invalid',
                long_desc='',
            ),
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='algo:ecc:invalid',
                long_desc='',
            ),
        ],
        'glep63-2-draft-20180707': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:ecc:invalid',
                long_desc='',
            ),
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='algo:ecc:invalid',
                long_desc='',
            ),
        ],
        'glep63-2.1': [
            KeyIssue(
                key=KEY,
                machine_desc='algo:ecc:invalid',
                long_desc='',
            ),
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[0],
                machine_desc='algo:ecc:invalid',
                long_desc='',
            ),
            SubKeyIssue(
                key=KEY,
                subkey=KEY.subkeys[1],
                machine_desc='algo:ecc:invalid',
                long_desc='',
            ),
        ],
    }

    def test_integration(self):
        for vl in tests.key_base.get_gnupg_version().splitlines():
            if vl.startswith(b'Pubkey:') and b'ECDSA' in vl:
                break
        else:
            raise unittest.SkipTest('GnuPG does not seem to have ECDSA support')

        super(NISTP256Test, self).test_integration()
