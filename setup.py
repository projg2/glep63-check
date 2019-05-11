#!/usr/bin/env python3
# (C) 2018 Michał Górny <mgorny@gentoo.org>
# Released under the terms of the 2-clause BSD license.

from distutils.core import setup


setup(
    name='glep63-check',
    version='9',
    author='Michał Górny',
    author_email='mgorny@gentoo.org',
    url='http://github.com/mgorny/glep63-verify',

    packages=['glep63'],
    scripts=['glep63-check'],

    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Topic :: Security :: Cryptography'
    ]
)
