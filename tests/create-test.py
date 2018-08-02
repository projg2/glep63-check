#!/usr/bin/env python
# Write a test case based on key file.
# (c) 2018 Michał Górny
# Released under the terms of 2-clause BSD license.

import enum
import io
import os.path
import subprocess
import sys

sys.path.insert(0, '.')

from glep63.check import (check_key,)
from glep63.gnupg import (process_gnupg_colons,)
from glep63.specs import (SPECS,)


def pretty_key(key, indent=4):
    out = '{}('.format(key.__class__.__name__)
    for k, v in key._asdict().items():
        # issue class special cases
        if k == 'key':
            v = 'KEY'
        elif k == 'subkey':
            v = 'KEY.subkeys[0]'
        elif k == 'uid':
            v = 'KEY.uids[0]'
        elif k == 'long_desc':
            v = repr('')
        elif isinstance(v, enum.Enum):
            v = '{}.{}'.format(v.__class__.__name__, v.name)
        elif isinstance(v, list):
            lv = '['
            for e in v:
                lv += ('\n{_:{padding}}{item},'
                        .format(_=' ', padding=indent+8,
                                item=pretty_key(e, indent=indent+8)))
            v = '{}\n{_:{padding}}]'.format(lv, _=' ', padding=indent+4)
        else:
            v = repr(v)

        out += '\n{_:{padding}}{k}={v},'.format(k=k, v=v, _=' ',
                                                padding=indent+4)
    out += '\n{_:{padding}})'.format(_=' ', padding=indent)
    return out


def pretty_result(result):
    if not result:
        return ''

    out = ''
    for r in result:
        out += '\n{_:{padding}}{v},'.format(v=pretty_key(r, indent=12),
                                           _=' ', padding=12)

    return '{}\n{_:{padding}}'.format(out, _=' ', padding=8)


def pretty_results(results):
    out = '{'
    for k, v in sorted(results.items()):
        out += '\n{_:{indent}}{k}: [{v}],'.format(k=repr(k),
                                                v=pretty_result(v),
                                                _=' ', indent=8)
    out += '\n    }'
    return out


def main(key_path, test_name):
    with subprocess.Popen(['gpg', '--no-default-keyring',
            '--keyring', key_path, '--list-key', '--with-colons'],
            stdout=subprocess.PIPE) as s:
        key_colons, _ = s.communicate()
        assert s.wait() == 0

    key_colons = key_colons.decode('ASCII')
    with io.StringIO(key_colons) as f:
        key_cls = process_gnupg_colons(f)

    assert len(key_cls) == 1
    key_cls = key_cls[0]

    results = {}
    for k, spec in SPECS.items():
        results[k] = check_key(key_cls, spec)

    print('''

class {test_name}(tests.key_base.BaseKeyTest):
    KEY_FILE = '{key_file}'

    GPG_COLONS = \'\'\'
{gpg_colons}\'\'\'

    KEY = {key_cls}

    EXPECTED_RESULTS = {expected}'''.format(
        test_name=test_name,
        key_file=os.path.relpath(key_path, 'tests'),
        gpg_colons=key_colons,
        key_cls=pretty_key(key_cls),
        expected=pretty_results(results)))


if __name__ == '__main__':
    main(*sys.argv[1:])
