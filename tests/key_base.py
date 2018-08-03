# glep63-check -- base class for key tests
# (c) 2018 Michał Górny
# Released under the terms of 2-clause BSD license.

import datetime
import io
import os.path
import subprocess
import unittest
import unittest.mock

from glep63.check import (check_key,)
from glep63.gnupg import (process_gnupg_key, process_gnupg_colons,
                          spawn_gnupg)
from glep63.specs import (SPECS,)


class FakeTimePopen(subprocess.Popen):
    def __init__(self, cmd, *args, **kwargs):
        cmd = ['faketime', '-f', '2018-08-03 00:00:00'] + cmd
        try:
            return super(FakeTimePopen, self).__init__(cmd, *args, **kwargs)
        except FileNotFoundError:
            raise unittest.SkipTest(
                    'faketime is required to run GPG integration tests')


class PatchedDateTime(datetime.datetime):
    @classmethod
    def utcnow(self):
        return datetime.datetime(2018, 8, 3)


def clear_long_descs(it):
    """
    Rewrite all issue classes in @it not to contain long_desc
    (for better comparison).
    """
    for e in it:
        yield e._replace(long_desc='')


GNUPG_VERSION = None


def get_gnupg_version():
    global GNUPG_VERSION
    if GNUPG_VERSION is None:
        try:
            with spawn_gnupg(['--version'],
                             stdout=subprocess.PIPE,
                             env={'LANG': 'C'}) as s:
                sout, serr = s.communicate()
                if s.wait() != 0:
                    GNUPG_VERSION = ''
                else:
                    GNUPG_VERSION = sout
        except FileNotFoundError:
            GNUPG_VERSION = ''

    return GNUPG_VERSION


class BaseKeyTest(unittest.TestCase):
    def test_key_class(self):
        """
        Test the key using predefined Key class.
        """
        keys = [self.KEY]

        with unittest.mock.patch("datetime.datetime", PatchedDateTime):
            for spec, expected in self.EXPECTED_RESULTS.items():
                with self.subTest(spec):
                    self.assertListEqual(expected,
                            list(clear_long_descs(
                                check_key(keys[0], SPECS[spec]))))

    def test_colons(self):
        """
        Test the key using provided 'gpg --with-colons' output.
        """
        keys = process_gnupg_colons(io.StringIO(self.GPG_COLONS))
        assert len(keys) == 1

        with unittest.mock.patch("datetime.datetime", PatchedDateTime):
            for spec, expected in self.EXPECTED_RESULTS.items():
                with self.subTest(spec):
                    self.assertListEqual(expected,
                            list(clear_long_descs(
                                check_key(keys[0], SPECS[spec]))))

    def test_integration(self):
        """
        Test the key using local installed GnuPG.
        """
        if not get_gnupg_version():
            raise unittest.SkipTest('GnuPG executable not found')

        keypath = os.path.join(os.path.dirname(__file__), self.KEY_FILE)
        with unittest.mock.patch("glep63.gnupg.subprocess.Popen", FakeTimePopen):
            keys = process_gnupg_key(keyrings=[keypath])
        assert len(keys) == 1

        with unittest.mock.patch("datetime.datetime", PatchedDateTime):
            for spec, expected in self.EXPECTED_RESULTS.items():
                with self.subTest(spec):
                    self.assertListEqual(expected,
                            list(clear_long_descs(
                                check_key(keys[0], SPECS[spec]))))
