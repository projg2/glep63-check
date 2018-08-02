# glep63-check -- base types and constants
# (c) 2018 Michał Górny
# Released under the terms of 2-clause BSD license.

import collections
import enum


key_keys = ('validity', 'key_length', 'key_algo', 'keyid',
            'creation_date', 'expiration_date', 'key_caps',
            'curve')

# tuples for "gpg --with-colons" output
Key = collections.namedtuple('Key', key_keys)
PublicKey = collections.namedtuple('PublicKey',
    key_keys + ('subkeys', 'uids'))
UID = collections.namedtuple('UID',
    ('validity', 'creation_date', 'expiration_date', 'uid_hash',
     'user_id'))


# gpg/openpgp consts
class Validity(str, enum.Enum):
    INVALID = 'i'
    REVOKED = 'r'
    EXPIRED = 'e'


class KeyAlgo(enum.IntEnum):
    RSA                 = 1
    RSA_ENCRYPT_ONLY    = 2
    RSA_SIGN_ONLY       = 3
    ELGAMAL             = 16
    DSA                 = 17
    ECDH                = 18
    ECDSA               = 19
    EDDSA               = 22


KeyIssue = collections.namedtuple('KeyIssue',
    ('key', 'machine_desc', 'long_desc'))
KeyWarning = collections.namedtuple('KeyWarning',
    ('key', 'machine_desc', 'long_desc'))


SubKeyIssue = collections.namedtuple('SubKeyIssue',
    ('key', 'subkey', 'machine_desc', 'long_desc'))
SubKeyWarning = collections.namedtuple('SubKeyWarning',
    ('key', 'subkey', 'machine_desc', 'long_desc'))


UIDIssue = collections.namedtuple('UIDIssue',
    ('key', 'uid', 'machine_desc', 'long_desc'))


IssueClasses = collections.namedtuple('IssueClasses',
    ('key', 'subkey', 'uid'))


FAIL = IssueClasses(KeyIssue, SubKeyIssue, UIDIssue)
WARN = IssueClasses(KeyWarning, SubKeyWarning, None)


class Years(object):
    def __init__(self, val):
        self.years = val

    @property
    def days(self):
        return self.years * 365.24

    def __str__(self):
        return '{} years'.format(self.years)


class Days(object):
    def __init__(self, val):
        self.days = val

    def __str__(self):
        return '{} days'.format(self.days)
