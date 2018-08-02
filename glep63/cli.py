# glep63-check -- command-line interface
# (c) 2018 Michał Górny
# Released under the terms of 2-clause BSD license.

import argparse
import io
import subprocess

from glep63.base import (FAIL, WARN)
from glep63.check import (check_key,)
from glep63.gnupg import (process_gnupg_colons,)
from glep63.specs import (SPECS, DEFAULT_SPEC)


def main():
    argp = argparse.ArgumentParser()
    act = argp.add_mutually_exclusive_group(required=True)
    act.add_argument('-a', '--all', action='store_true',
            help='Verify all public keys in the local keyring')
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
    argp.add_argument('-w', '--warnings-as-errors', action='store_true',
            help='Treat warnings as errors (return unsucessfully if any)')

    opts = argp.parse_args()

    keys = []

    if opts.key_id is not None or opts.all or opts.keyring is not None:
        cmd = ['gpg', '--with-colons', '--list-keys', '--fixed-list-mode']
        if opts.keyring is not None:
            cmd += ['--no-default-keyring']
            for k in opts.keyring:
                cmd += ['--keyring', k]
        if opts.key_id is not None:
            cmd += opts.key_id
        s = subprocess.Popen(cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE)
        sout = io.TextIOWrapper(s.stdout, encoding='UTF-8')
        keys = process_gnupg_colons(sout)
        if s.wait() != 0:
            print('Warning: GnuPG exited unnecessfully!')
    elif opts.gnupg is not None:
        for f in opts.gnupg:
            keys.extend(process_gnupg_colons(f))

    out = []
    for k in keys:
        out.extend(check_key(k, SPECS[opts.spec]))

    ret = 0
    for i in out:
        keyid = i.key.keyid
        if hasattr(i, 'subkey'):
            keyid += ':' + i.subkey.keyid
        elif hasattr(i, 'uid'):
            keyid += ':[{}]'.format(i.uid.user_id)

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
            # decorate with readable UID
            sorted_uids = sorted(i.key.uids,
                    key=lambda x: not '@gentoo.org' in x.user_id)
            uid = '[{}]'.format(sorted_uids[0].user_id)
            msg = [keyid, uid, cls, i.machine_desc, i.long_desc]

        print(' '.join(msg))

    return ret
