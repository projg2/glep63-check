# glep63-check -- command-line interface
# (c) 2018 Michał Górny
# Released under the terms of 2-clause BSD license.

import argparse
import email.utils
import shutil
import tempfile
import urllib.request

from glep63.base import (FAIL, WARN)
from glep63.check import (check_key,)
from glep63.gnupg import (process_gnupg_colons, process_gnupg_key)
from glep63.specs import (SPECS, DEFAULT_SPEC)


def main():
    argp = argparse.ArgumentParser()
    act = argp.add_mutually_exclusive_group(required=True)
    act.add_argument('-a', '--all', action='store_true',
            help='Verify all public keys in the local keyring')
    act.add_argument('-d', '--developers', action='store_true',
            help='Fetch and verify keys for gentoo.git committers')
    act.add_argument('-D', '--all-developers', action='store_true',
            help='Fetch and verify keys for all Gentoo developers')
    act.add_argument('-G', '--gnupg',
            nargs='+', metavar='FILE', type=argparse.FileType('r', encoding='UTF-8'),
            help='Process "gpg --with-colons" output from FILE(s) ("-" for stdin)')
    act.add_argument('-k', '--key-id', nargs='+',
            help='Check local GnuPG keys matching specified query (IDs, names)')
    act.add_argument('-K', '--keyring', nargs='+',
            help='Check all keys in specified keyrings (gpg --keyring syntax)')

    argp.add_argument('-S', '--spec', choices=SPECS, default=DEFAULT_SPEC,
            help='Spec to verify against')
    argp.add_argument('-e', '--errors-only', action='store_true',
            help='Print only errors (skip warnings)')
    argp.add_argument('-m', '--machine-readable', action='store_true',
            help='Print only machine-readable data (skip human-readable desc)')
    argp.add_argument('-N', '--no-name', action='store_true',
            help='Print only e-mail addresses as UIDs')
    argp.add_argument('-w', '--warnings-as-errors', action='store_true',
            help='Treat warnings as errors (return unsucessfully if any)')

    opts = argp.parse_args()

    keys = []

    if opts.developers or opts.all_developers:
        keyring_url = ('https://qa-reports.gentoo.org/output/{}.gpg'
                       .format('committing-devs' if opts.developers
                               else 'active-devs'))
        with urllib.request.urlopen(keyring_url) as f:
            with tempfile.NamedTemporaryFile() as tmpf:
                shutil.copyfileobj(f, tmpf)
                tmpf.flush()
                keys.extend(process_gnupg_key([tmpf.name], opts.key_id))
    elif opts.key_id is not None or opts.all or opts.keyring is not None:
        keys.extend(process_gnupg_key(opts.keyring, opts.key_id))
    elif opts.gnupg is not None:
        for f in opts.gnupg:
            keys.extend(process_gnupg_colons(f))

    out = []
    for k in keys:
        out.extend(check_key(k, SPECS[opts.spec]))

    ret = 0
    for i in out:
        # figure out a primary UID, preferring @gentoo.org
        primary_uid = i.key.uids[0].user_id
        for x in i.key.uids:
            if '@gentoo.org' in x.user_id:
                primary_uid = x.user_id
                break
        _, uid_addr = email.utils.parseaddr(primary_uid)

        keyid = i.key.keyid
        if hasattr(i, 'subkey'):
            keyid += ':' + i.subkey.keyid
        elif hasattr(i, 'uid'):
            if opts.no_name:
                _, uid_fmt = email.utils.parseaddr(i.uid_user_id)
            else:
                uid_fmt = i.uid.user_id
            keyid += ':[{}]'.format(uid_fmt)

        if type(i) in FAIL:
            ret |= 1
            cls = '[E]'
        else:
            assert type(i) in WARN
            cls = '[W]'
            if opts.errors_only:
                continue
            if opts.warnings_as_errors:
                ret |= 2

        if opts.machine_readable:
            msg = [keyid, i.machine_desc]
        else:
            msg = [keyid, '[{}]'.format(
                uid_addr if opts.no_name else primary_uid),
                cls, i.machine_desc, i.long_desc]

        print(' '.join(msg))

    return ret
