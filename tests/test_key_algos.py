# glep63-check -- tests for issues related to key algos
# (c) 2018 Michał Górny
# Released under the terms of 2-clause BSD license.

import datetime
import unittest

from glep63.base import (PublicKey, Key, UID, KeyAlgo, Validity,
        KeyWarning, KeyIssue, SubKeyWarning, SubKeyIssue)

import tests.key_base


class RSA4096GoodKeyTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/rsa4096-good.gpg'

    GPG_COLONS = '''
pub:-:4096:1:1CA702E06E4BCC77:1533197590:1564733590::-:::scSC::::::23::0:
fpr:::::::::76D807795BF5E849A5577D631CA702E06E4BCC77:
uid:-::::1533197590::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:7D36F079CF0CA133:1533197744:1564733744:::::s::::::23:
fpr:::::::::62D59FE2046463CD65D44A247D36F079CF0CA133:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='1CA702E06E4BCC77',
        creation_date=datetime.datetime(2018, 8, 2, 8, 13, 10),
        expiration_date=datetime.datetime(2019, 8, 2, 8, 13, 10),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='7D36F079CF0CA133',
                creation_date=datetime.datetime(2018, 8, 2, 8, 15, 44),
                expiration_date=datetime.datetime(2019, 8, 2, 8, 15, 44),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 8, 13, 10),
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


class RSA2048GoodKeyTest(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/rsa2048-good.gpg'

    GPG_COLONS = '''
pub:-:2048:1:1F6B066F475D64D5:1533202733:1564738733::-:::scSC::::::23::0:
fpr:::::::::F5C22BDE86B2400D8CB1F71F1F6B066F475D64D5:
uid:-::::1533202733::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:2048:1:D8A0594E89EBEDD6:1533202745:1564738745:::::s::::::23:
fpr:::::::::56C11AFCB2ABF83B107E928AD8A0594E89EBEDD6:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=2048,
        key_algo=KeyAlgo.RSA,
        keyid='1F6B066F475D64D5',
        creation_date=datetime.datetime(2018, 8, 2, 9, 38, 53),
        expiration_date=datetime.datetime(2019, 8, 2, 9, 38, 53),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=2048,
                key_algo=KeyAlgo.RSA,
                keyid='D8A0594E89EBEDD6',
                creation_date=datetime.datetime(2018, 8, 2, 9, 39, 5),
                expiration_date=datetime.datetime(2019, 8, 2, 9, 39, 5),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 9, 38, 53),
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
    }


class RSA4096Sub2048Test(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/rsa4096-2048.gpg'

    GPG_COLONS = '''
pub:-:4096:1:CFA2E0E6173BEC9D:1533208139:1564744139::-:::scSC::::::23::0:
fpr:::::::::191F67DCA0EF7FB205CAAC5ACFA2E0E6173BEC9D:
uid:-::::1533208139::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:2048:1:55F6865D44767A2E:1533208150:1564744150:::::s::::::23:
fpr:::::::::C5FA2770E5F8DDF7F9B96F1B55F6865D44767A2E:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='CFA2E0E6173BEC9D',
        creation_date=datetime.datetime(2018, 8, 2, 11, 8, 59),
        expiration_date=datetime.datetime(2019, 8, 2, 11, 8, 59),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=2048,
                key_algo=KeyAlgo.RSA,
                keyid='55F6865D44767A2E',
                creation_date=datetime.datetime(2018, 8, 2, 11, 9, 10),
                expiration_date=datetime.datetime(2019, 8, 2, 11, 9, 10),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 11, 8, 59),
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
    }


class RSA1024Sub4096Test(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/rsa1024-4096.gpg'

    GPG_COLONS = '''
pub:-:1024:1:9B18476870213E0F:1533208302:1564744302::-:::scSC::::::::0:
fpr:::::::::E214CBE1E4CE91B6DCE3AE7F9B18476870213E0F:
uid:-::::1533208302::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:C25D452B1ED889DD:1533208312:1564744312:::::s::::::23:
fpr:::::::::DF1B379EC6E3CDF79F2D030BC25D452B1ED889DD:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=1024,
        key_algo=KeyAlgo.RSA,
        keyid='9B18476870213E0F',
        creation_date=datetime.datetime(2018, 8, 2, 11, 11, 42),
        expiration_date=datetime.datetime(2019, 8, 2, 11, 11, 42),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='C25D452B1ED889DD',
                creation_date=datetime.datetime(2018, 8, 2, 11, 11, 52),
                expiration_date=datetime.datetime(2019, 8, 2, 11, 11, 52),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 11, 11, 42),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    COMMON_ISSUE = KeyIssue(
        key=KEY,
        machine_desc='algo:rsa:tooshort',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [COMMON_ISSUE],
        'glep63-1-rsa2048-ec25519': [COMMON_ISSUE],
        'glep63-1-strict': [COMMON_ISSUE],
        'glep63-2': [COMMON_ISSUE],
        'glep63-2-draft-20180707': [COMMON_ISSUE],
    }


class DSA2048RSA4096Test(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/dsa2048-rsa4096.gpg'

    GPG_COLONS = '''
pub:-:2048:17:968768FEBAAD6E49:1533208644:1564744644::-:::scSC::::::23::0:
fpr:::::::::A504A59F39B3C0F49F551D2B968768FEBAAD6E49:
uid:-::::1533208644::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:55FD297325EAA2B5:1533208655:1564744655:::::s::::::23:
fpr:::::::::9954BCDA16332A3C380DAE3C55FD297325EAA2B5:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=2048,
        key_algo=KeyAlgo.DSA,
        keyid='968768FEBAAD6E49',
        creation_date=datetime.datetime(2018, 8, 2, 11, 17, 24),
        expiration_date=datetime.datetime(2019, 8, 2, 11, 17, 24),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='55FD297325EAA2B5',
                creation_date=datetime.datetime(2018, 8, 2, 11, 17, 35),
                expiration_date=datetime.datetime(2019, 8, 2, 11, 17, 35),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 11, 17, 24),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    DSA_WARNING = KeyWarning(
        key=KEY,
        machine_desc='algo:dsa:discouraged',
        long_desc='',
    )
    DSA_FAIL = KeyIssue(
        key=KEY,
        machine_desc='algo:dsa',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [DSA_WARNING],
        'glep63-1-rsa2048-ec25519': [DSA_WARNING],
        'glep63-1-strict': [DSA_WARNING],
        'glep63-2': [DSA_FAIL],
        'glep63-2-draft-20180707': [DSA_FAIL],
    }


class RSA4096DSA2048Test(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/rsa4096-dsa2048.gpg'

    GPG_COLONS = '''
pub:-:4096:1:08C3F5E44D93E07D:1533208882:1564744882::-:::scSC::::::23::0:
fpr:::::::::50CED1D4EAC31BEAE6671AA408C3F5E44D93E07D:
uid:-::::1533208882::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:2048:17:F446AAD172206DB4:1533208899:1564744899:::::s::::::23:
fpr:::::::::0BF23B92F74AB354BE52890EF446AAD172206DB4:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=4096,
        key_algo=KeyAlgo.RSA,
        keyid='08C3F5E44D93E07D',
        creation_date=datetime.datetime(2018, 8, 2, 11, 21, 22),
        expiration_date=datetime.datetime(2019, 8, 2, 11, 21, 22),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=2048,
                key_algo=KeyAlgo.DSA,
                keyid='F446AAD172206DB4',
                creation_date=datetime.datetime(2018, 8, 2, 11, 21, 39),
                expiration_date=datetime.datetime(2019, 8, 2, 11, 21, 39),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 11, 21, 22),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    DSA_WARNING = SubKeyWarning(
        key=KEY,
        subkey=KEY.subkeys[0],
        machine_desc='algo:dsa:discouraged',
        long_desc='',
    )
    DSA_FAIL = SubKeyIssue(
        key=KEY,
        subkey=KEY.subkeys[0],
        machine_desc='algo:dsa',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [DSA_WARNING],
        'glep63-1-rsa2048-ec25519': [DSA_WARNING],
        'glep63-1-strict': [DSA_WARNING],
        'glep63-2': [DSA_FAIL],
        'glep63-2-draft-20180707': [DSA_FAIL],
    }


class DSA1024RSA4096Test(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/dsa1024-rsa4096.gpg'

    GPG_COLONS = '''
pub:-:1024:17:AAD1EF4334F3B96B:1533209185:1564745185::-:::scSC::::::::0:
fpr:::::::::DA808479AE6746FD138C6583AAD1EF4334F3B96B:
uid:-::::1533209185::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:4096:1:D1F001792D7EB70D:1533209210:1564745210:::::s::::::23:
fpr:::::::::827312B653BFA33304932F8ED1F001792D7EB70D:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=1024,
        key_algo=KeyAlgo.DSA,
        keyid='AAD1EF4334F3B96B',
        creation_date=datetime.datetime(2018, 8, 2, 11, 26, 25),
        expiration_date=datetime.datetime(2019, 8, 2, 11, 26, 25),
        key_caps='scSC',
        curve='',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=4096,
                key_algo=KeyAlgo.RSA,
                keyid='D1F001792D7EB70D',
                creation_date=datetime.datetime(2018, 8, 2, 11, 26, 50),
                expiration_date=datetime.datetime(2019, 8, 2, 11, 26, 50),
                key_caps='s',
                curve='',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 11, 26, 25),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    DSA_SHORT = KeyIssue(
        key=KEY,
        machine_desc='algo:dsa:tooshort',
        long_desc='',
    )
    DSA_FAIL = KeyIssue(
        key=KEY,
        machine_desc='algo:dsa',
        long_desc='',
    )

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': [DSA_SHORT],
        'glep63-1-rsa2048-ec25519': [DSA_SHORT],
        'glep63-1-strict': [DSA_SHORT],
        'glep63-2': [DSA_FAIL],
        'glep63-2-draft-20180707': [DSA_FAIL],
    }


class ED25519Test(tests.key_base.BaseKeyTest):
    KEY_FILE = 'algos/ed25519.gpg'

    GPG_COLONS = '''
pub:-:256:22:EBD990BE5ABC63BF:1533209443:1564745443::-:::scSC:::::ed25519:::0:
fpr:::::::::16EC7DF23F5BF50CC6514D2FEBD990BE5ABC63BF:
uid:-::::1533209443::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:256:22:09BE3D8938DA35DF:1533209464:1564745464:::::s:::::ed25519::
fpr:::::::::4E0F2E5F105580797681E1A109BE3D8938DA35DF:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=256,
        key_algo=KeyAlgo.EDDSA,
        keyid='EBD990BE5ABC63BF',
        creation_date=datetime.datetime(2018, 8, 2, 11, 30, 43),
        expiration_date=datetime.datetime(2019, 8, 2, 11, 30, 43),
        key_caps='scSC',
        curve='ed25519',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=256,
                key_algo=KeyAlgo.EDDSA,
                keyid='09BE3D8938DA35DF',
                creation_date=datetime.datetime(2018, 8, 2, 11, 31, 4),
                expiration_date=datetime.datetime(2019, 8, 2, 11, 31, 4),
                key_caps='s',
                curve='ed25519',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 11, 30, 43),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    V1_ISSUES = [
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
    ]

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': V1_ISSUES,
        'glep63-1-rsa2048-ec25519': [],
        'glep63-1-strict': V1_ISSUES,
        'glep63-2': [],
        'glep63-2-draft-20180707': [],
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
tru::1:1533016006:1589192747:3:1:5
pub:-:256:19:39540E8CD11EB1B7:1533209647:1564745647::-:::scSC:::::nistp256:::0:
fpr:::::::::8FAA697663EED630FA7D9B4F39540E8CD11EB1B7:
uid:-::::1533209647::0DAFDC73F43FC173C2216BA2BB4928391676BF2F::GLEP63 test key <nobody@gentoo.org>::::::::::0:
sub:-:256:19:12ACFB3AB4BD7F21:1533209664:1564745664:::::s:::::nistp256::
fpr:::::::::AE5287337CFB57FB09E10BE412ACFB3AB4BD7F21:
'''

    KEY = PublicKey(
        validity=Validity.NO_VALUE,
        key_length=256,
        key_algo=KeyAlgo.ECDSA,
        keyid='39540E8CD11EB1B7',
        creation_date=datetime.datetime(2018, 8, 2, 11, 34, 7),
        expiration_date=datetime.datetime(2019, 8, 2, 11, 34, 7),
        key_caps='scSC',
        curve='nistp256',
        subkeys=[
            Key(
                validity=Validity.NO_VALUE,
                key_length=256,
                key_algo=KeyAlgo.ECDSA,
                keyid='12ACFB3AB4BD7F21',
                creation_date=datetime.datetime(2018, 8, 2, 11, 34, 24),
                expiration_date=datetime.datetime(2019, 8, 2, 11, 34, 24),
                key_caps='s',
                curve='nistp256',
            ),
        ],
        uids=[
            UID(
                validity=Validity.NO_VALUE,
                creation_date=datetime.datetime(2018, 8, 2, 11, 34, 7),
                expiration_date=None,
                uid_hash='0DAFDC73F43FC173C2216BA2BB4928391676BF2F',
                user_id='GLEP63 test key <nobody@gentoo.org>',
            ),
        ],
    )

    V1_ISSUES = [
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
    ]
    V2_ISSUES = [
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
    ]

    EXPECTED_RESULTS = {
        'glep63-1-rsa2048': V1_ISSUES,
        'glep63-1-rsa2048-ec25519': V2_ISSUES,
        'glep63-1-strict': V1_ISSUES,
        'glep63-2': V2_ISSUES,
        'glep63-2-draft-20180707': V2_ISSUES,
    }

    def test_integration(self):
        for vl in tests.key_base.get_gnupg_version().splitlines():
            if vl.startswith(b'Pubkey:') and b'ECDSA' in vl:
                break
        else:
            raise unittest.SkipTest('GnuPG does not seem to have ECDSA support')

        super(NISTP256Test, self).test_integration()
