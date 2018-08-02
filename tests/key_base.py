# glep63-check -- base class for key tests
# (c) 2018 Michał Górny
# Released under the terms of 2-clause BSD license.

import io
import os.path
import unittest

from glep63.check import (check_key,)
from glep63.gnupg import (process_gnupg_key, process_gnupg_colons)
from glep63.specs import (SPECS,)


def clear_long_descs(it):
    """
    Rewrite all issue classes in @it not to contain long_desc
    (for better comparison).
    """
    for e in it:
        yield e._replace(long_desc='')


class BaseKeyTest(unittest.TestCase):
    def test_key_class(self):
        """
        Test the key using predefined Key class.
        """
        keys = [self.KEY]

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

        for spec, expected in self.EXPECTED_RESULTS.items():
            with self.subTest(spec):
                self.assertListEqual(expected,
                        list(clear_long_descs(
                            check_key(keys[0], SPECS[spec]))))

    def test_integration(self):
        """
        Test the key using local installed GnuPG.
        """
        keypath = os.path.join(os.path.dirname(__file__), self.KEY_FILE)
        keys = process_gnupg_key(keyrings=[keypath])
        assert len(keys) == 1

        for spec, expected in self.EXPECTED_RESULTS.items():
            with self.subTest(spec):
                self.assertListEqual(expected,
                        list(clear_long_descs(
                            check_key(keys[0], SPECS[spec]))))
