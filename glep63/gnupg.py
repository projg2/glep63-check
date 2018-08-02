# glep63-check -- GnuPG output processing
# (c) 2018 Michał Górny
# Released under the terms of 2-clause BSD license.

import datetime
import errno
import io
import subprocess

from glep63.base import (Key, PublicKey, UID, KeyAlgo, Validity)


def process_date(d):
    if d == '':
        return None
    elif 'T' in d:
        return datetime.datetime.strptime(d, '%Y%m%dT%H%M%S')
    else:
        return datetime.datetime.utcfromtimestamp(int(d))


def process_initial_key_fields(validity, key_length, key_algo, keyid,
        creation_date, expiration_date):
    return (
        Validity(validity),
        int(key_length),
        KeyAlgo(int(key_algo)),
        keyid,
        process_date(creation_date),
        process_date(expiration_date),
    )


def process_gnupg_colons(f):
    """
    Process "gpg --with-colons" output from stream @f, and into list
    of key objects.
    """

    keys = []

    for l in f:
        vals = l.split(':')

        # type of record
        if vals[0] == 'pub':
            keys.append(PublicKey(
                *process_initial_key_fields(*vals[1:7]) +
                (vals[11], vals[16] if vals[16:17] else '', [], [])))
        elif vals[0] == 'sub':
            assert keys
            keys[-1].subkeys.append(Key(
                *(process_initial_key_fields(*vals[1:7]) +
                (vals[11], vals[16] if vals[16:17] else ''))))
        elif vals[0] == 'uid':
            assert keys
            keys[-1].uids.append(UID(Validity(vals[1]),
                process_date(vals[5]), process_date(vals[6]),
                vals[7], vals[9]))

    return keys


def process_gnupg_key(keyrings=None, keyids=None):
    """
    Call gpg to get key information.

    @keyrings specifies a list of alternate keyrings to use.  If None,
    the default keyring is used.

    @keyids specifies a list of keys to process.  If None, all keys
    in the keyring(s) are processed.
    """

    # prefer gpg2 on systems using split executables
    for gpg_tool in ('gpg2', 'gpg'):
        cmd = [gpg_tool, '--with-colons', '--list-keys', '--fixed-list-mode']
        if keyrings is not None:
            cmd += ['--no-default-keyring']
            for k in keyrings:
                cmd += ['--keyring', k]
        if keyids is not None:
            cmd += keyids

        try:
            with subprocess.Popen(cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE) as s:
                with io.TextIOWrapper(s.stdout, encoding='UTF-8') as sout:
                    keys = process_gnupg_colons(sout)
                    if s.wait() != 0:
                        raise subprocess.CalledProcessError(s.returncode, cmd)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
            last_except = e
            continue
        else:
            break
    else:
        raise last_except

    return keys
