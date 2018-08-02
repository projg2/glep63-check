# glep63-check -- key checking procedure
# (c) 2018 Michał Górny
# Released under the terms of 2-clause BSD license.

import datetime
import email.utils
import functools

from glep63.base import (FAIL, WARN, KeyAlgo, Validity, KeyIssue,
        SubKeyIssue, UIDIssue)


def check_subkey(k, spec, key_type, issue_params):
    out = []

    issue_cls = functools.partial(getattr(FAIL, key_type), *issue_params)
    warning_cls = functools.partial(getattr(WARN, key_type), *issue_params)

    # 1. key algo/length
    if k.key_algo in (KeyAlgo.RSA_SIGN_ONLY, KeyAlgo.RSA_ENCRYPT_ONLY):
        out.append(warning_cls('algo:rsa:deprecated_only',
            'Sign-only/encrypt-only RSA keys are deprecated'))
        # set to common value for simplicity
        k.key_algo = KeyAlgo.RSA

    if k.key_algo in (KeyAlgo.DSA, KeyAlgo.ELGAMAL):
        dsa_key = spec.get('algo:dsa')
        if dsa_key == FAIL:
            out.append(issue_cls('algo:dsa',
                'DSA keys are disallowed (RSA is recommended)'))
        elif k.key_length < spec.get('algo:dsa:minlength', 0):
            out.append(issue_cls('algo:dsa:tooshort',
                'DSA key too short (has {} bits, should be {} bits)'
                .format(k.key_length, spec['algo:dsa:minlength'])))
        elif dsa_key == WARN:
            out.append(warning_cls('algo:dsa:discouraged',
                'DSA keys are discouraged (RSA is recommended)'))
    elif k.key_algo == KeyAlgo.RSA:
        rsa_key = spec.get('algo:rsa')
        # we currently don't have to implement forbidding RSA ;-)
        assert not rsa_key
        if k.key_length < spec.get('algo:rsa:minlength', 0):
            out.append(issue_cls('algo:rsa:tooshort',
                'RSA key too short (has {} bits, should be at least {} bits)'
                .format(k.key_length, spec['algo:rsa:minlength'])))
        elif k.key_length < spec.get('algo:rsa:recommended', 0):
            out.append(warning_cls('algo:rsa:short',
                'RSA key short (has {} bits, {} bits recommended)'
                .format(k.key_length, spec['algo:rsa:recommended'])))
    elif k.key_algo in (KeyAlgo.ECDH, KeyAlgo.ECDSA, KeyAlgo.EDDSA):
        ecc_key = spec.get('algo:ec25519')
        if ecc_key == FAIL:
            out.append(issue_cls('algo:ecc',
                'ECC keys are disallowed (RSA is recommended)'))
        else:
            # warnings are not used at the moment
            assert ecc_key is None

            if k.curve not in ('ec25519', 'ed25519'):
                out.append(issue_cls('algo:ecc:invalid',
                    'ECC curve {} disallowed (only Curve 25519 supported)'
                    .format(k.curve)))

    elif spec.get('algo:invalid'):
        cls = issue_cls if spec['algo:invalid'] == FAIL else warning_cls
        out.append(issue_cls('algo:invalid',
            'Unexpected key algorithm'))

    # 2. key expiration
    expire_max = spec.get('expire:max:{}'.format(key_type))
    expire_recommended = spec.get('expire:recommended:{}'.format(key_type))
    if expire_max is not None or expire_recommended is not None:
        if expire_recommended is not None:
            expire_str = ('<{} recommended, {} max'
                    .format(expire_recommended, expire_max))
        else:
            expire_str = '{} max'.format(expire_max)

        if k.expiration_date is None:
            cls = issue_cls if expire_max is not None else warning_cls
            out.append(cls('expire:none',
                'No expiration date on public key ({})'.format(expire_str)))
        else:
            expire_left = k.expiration_date - datetime.datetime.utcnow()
            if expire_max is not None and expire_left.days > expire_max.days:
                out.append(issue_cls('expire:long',
                    'Expiration date is too long (is {}, {})'
                    .format(k.expiration_date, expire_str)))
            elif (expire_recommended is not None
                    and expire_left.days > expire_recommended.days):
                out.append(warning_cls('expire:long',
                    'Expiration date is long (is {}, {})'
                    .format(k.expiration_date, expire_str)))
            elif (spec.get('expire:short') is not None
                    and expire_left.days < spec['expire:short:length'].days):
                cls = issue_cls if spec['expire:short'] == FAIL else warning_cls
                out.append(cls('expire:short',
                    'Expiration date is short (is {}, less than {})'
                    .format(k.expiration_date, spec['expire:short:length'])))

    return out


def check_key(k, spec):
    out = []

    # 0. check key validity (only for whole key)
    if k.validity == Validity.INVALID:
        out.append(KeyIssue(k, 'validity:invalid',
            'Public key is invalid'))
        return out
    elif k.validity == Validity.REVOKED:
        out.append(KeyIssue(k, 'validity:revoked',
            'Public key has been revoked'))
        return out
    elif k.validity == Validity.EXPIRED:
        out.append(KeyIssue(k, 'validity:expired',
            'Public key has expired'))
        return out

    # 1. check public key
    out.extend(check_subkey(k, spec, 'key', (k,)))

    # 2. check subkeys
    # (sadly, we can't be sure *which* subkey is used for Gentoo,
    #  so we complain about all of them)
    has_signing_subkey = False
    for sk in k.subkeys:
        # check only signing subkeys
        if 's' not in sk.key_caps:
            continue
        # complain about invalid subkeys
        if sk.validity == Validity.INVALID:
            out.append(SubKeyIssue(k, sk, 'validity:invalid',
                'Subkey is invalid'))
        # skip expired and revoked subkeys
        if sk.validity in (Validity.REVOKED, Validity.EXPIRED):
            continue

        if len(sk.key_caps) > 1 and spec.get('subkey:multipurpose'):
            out.append(spec['subkey:multipurpose'].subkey(k, sk, 'subkey:multipurpose',
                'Subkey has multiple capabilities enabled (has: [{}]; use dedicated subkeys!)'
                .format(sk.key_caps)))
        else:
            has_signing_subkey = True

        out.extend(check_subkey(sk, spec, 'subkey', (k, sk)))

    if not has_signing_subkey and spec.get('subkey:none'):
        out.append(spec['subkey:none'].key(k, 'subkey:none',
            'Having a dedicated signing subkey is required'))

    # 3. check UIDs
    # (require the @gentoo.org e-mail)
    has_gentoo_uid = False
    for u in k.uids:
        # complain about invalid UIDs
        if u.validity == Validity.INVALID:
            out.append(UIDIssue(k, u, 'validity:invalid',
                'UID is invalid'))
        # skip expired and revoked UIDs
        if u.validity in (Validity.REVOKED, Validity.EXPIRED):
            continue

        name, addr = email.utils.parseaddr(u.user_id)
        if addr.endswith('@gentoo.org'):
            has_gentoo_uid = True

    if not has_gentoo_uid and spec.get('uid:nogentoo'):
        out.append(spec['uid:nogentoo'].key(k, 'uid:nogentoo',
            '@gentoo.org e-mail not in key UIDs'))

    return out
