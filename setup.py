#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright (C) 2018 NuCypher

This file is part of pyUmbral.

pyUmbral is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

pyUmbral is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pyUmbral. If not, see <https://www.gnu.org/licenses/>.
"""

import os
import sys

from setuptools import setup
from setuptools.command.install import install


BASE_DIR = os.path.dirname(__file__)

ABOUT = dict()
with open(os.path.join(BASE_DIR, "umbral", "__about__.py")) as f:
    exec(f.read(), ABOUT)


with open(os.path.join(BASE_DIR, "README.rst")) as f:
    long_description = f.read()


class VerifyVersionCommand(install):
    """Custom command to verify that the git tag matches our version"""
    description = 'verify that the git tag matches our version'

    def run(self):
        tag = os.getenv('CIRCLE_TAG')
        if tag.startswith('v'):
            tag = tag[1:]

        version = ABOUT['__version__']
        if version.startswith('v'):
            version = version[1:]

        if tag != version:
            info = "Git tag: {0} does not match the version of this app: {1}".format(
                os.getenv('CIRCLE_TAG'), ABOUT['__version__']
            )
            sys.exit(info)


INSTALL_REQUIRES = ['setuptools',
                    'cryptography>=2.3',
                    'pynacl',
                    'byteStringSplitter',
                    'constant-sorrow',
                    ]

EXTRAS_REQUIRE = {'testing': ['bumpversion',
                              'hypothesis',
                              'pytest',
                              'pytest-mypy',
                              'pytest-mock',
                              'pytest-cov',
                              'mock',
                              'coverage',
                              'codecov',
                              'monkeytype==18.2.0',
                              'nbval',
                              'mypy',
                              ],

                  'docs': ['sphinx', 'sphinx-autobuild'],

                  'benchmarks': ['pytest-benchmark'],
                  }


setup(name=ABOUT['__title__'],
      url=ABOUT['__url__'],
      version=ABOUT['__version__'],
      author=ABOUT['__author__'],
      author_email=ABOUT['__email__'],
      description=ABOUT['__summary__'],
      long_description=long_description,
      extras_require=EXTRAS_REQUIRE,
      install_requires=INSTALL_REQUIRES,
      packages=['umbral'],
      classifiers=[
          "Development Status :: 2 - Pre-Alpha",
          "Intended Audience :: Science/Research",
          "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
          "Natural Language :: English",
          "Programming Language :: Python :: Implementation",
          "Programming Language :: Python :: 3 :: Only",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: 3.7",
          "Topic :: Scientific/Engineering",
        ],
      python_requires='>=3',
      cmdclass={'verify': VerifyVersionCommand}
      )
