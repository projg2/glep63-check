# glep63-check -- allowed key specifications
# (c) 2018 Michał Górny
# Released under the terms of 2-clause BSD license.

from glep63.base import (WARN, FAIL, Years, Days)


GLEP63_1_RSA2048 = {
    '__doc__': 'GLEP 63 v1 without RSA4096 preference',
    # subkey types to check
    '__subkey_types__': ['s'],
    # DSA key algorithm
    'algo:dsa': WARN,
    'algo:dsa:minlength': 2048,
    # RSA key algorithm
    'algo:rsa:minlength': 2048,
    # EC25519 algorithm
    'algo:ec25519': FAIL,
    # other algorithms
    'algo:invalid': FAIL,
    # expiration max values (fatal)
    'expire:max:key': Years(5),
    'expire:max:subkey': Years(5),
    # expiration recommended values (warning)
    'expire:recommended:key': Years(3),
    'expire:recommended:subkey': Years(1),
    # renewal
    'expire:short': WARN,
    'expire:short:length': Days(14),
    # multipurpose subkeys
    'subkey:multipurpose': WARN,
    # lack of signing subkey
    'subkey:none': FAIL,
    # lack of @gentoo.org UID
    'uid:nogentoo': WARN,
}

GLEP63_1_STRICT = GLEP63_1_RSA2048.copy()
GLEP63_1_STRICT.update({
    '__doc__': 'GLEP 63 v1 with RSA4096 preference',
    # RSA key algorithm
    'algo:rsa:recommended': 4096,
})

GLEP63_1_RSA2048_EC25519 = GLEP63_1_RSA2048.copy()
GLEP63_1_RSA2048_EC25519.update({
    '__doc__': 'GLEP 63 v1 with RSA2048 preference and allowed EC25519',
    # EC25519 algorithm
    'algo:ec25519': None,
})

GLEP63_2_DRAFT_20180707 = {
    '__doc__': 'GLEP 63 v2 draft as of 2018-07-07',
    # subkey types to check
    '__subkey_types__': ['s'],
    # DSA key algorithm
    'algo:dsa': FAIL,
    # RSA key algorithm
    'algo:rsa:minlength': 2048,
    # EC25519 algorithm
    'algo:ec25519': None,
    # other algorithms
    'algo:invalid': FAIL,
    # expiration max values (fatal)
    'expire:max:key': Days(900),
    'expire:max:subkey': Days(900),
    # renewal
    'expire:short': FAIL,
    'expire:short:length': Days(14),
    # multipurpose subkeys
    'subkey:multipurpose': WARN,
    # lack of signing subkey
    'subkey:none': FAIL,
    # lack of @gentoo.org UID
    'uid:nogentoo': WARN,
}

GLEP63_2 = GLEP63_2_DRAFT_20180707.copy()
GLEP63_2.update({
    '__doc__': 'GLEP 63 v2 as approved by the Council on 2018-07-29',
    'uid:nogentoo': FAIL,
})

GLEP63_2_1 = GLEP63_2.copy()
GLEP63_2_1.update({
    '__doc__': 'GLEP 63 v2.1 as approved by the Council on 2019-04-14',
    # subkey types to check
    '__subkey_types__': ['s', 'e'],
})


SPECS = {
    'glep63-1-rsa2048': GLEP63_1_RSA2048,
    'glep63-1-strict': GLEP63_1_STRICT,
    'glep63-1-rsa2048-ec25519': GLEP63_1_RSA2048_EC25519,
    'glep63-2-draft-20180707': GLEP63_2_DRAFT_20180707,
    'glep63-2': GLEP63_2,
    'glep63-2.1': GLEP63_2_1,
}

DEFAULT_SPEC = 'glep63-2.1'
