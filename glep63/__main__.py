# glep63-check -- main() wrapper
# (c) 2022 Michał Górny
# Released under the terms of 2-clause BSD license.

import sys

from glep63.cli import main


def entry_point():
    sys.exit(main())


if __name__ == '__main__':
    entry_point()
