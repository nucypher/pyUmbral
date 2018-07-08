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
from distutils.core import setup

BASE_DIR = os.path.dirname(__file__)

ABOUT = dict()
with open(os.path.join(BASE_DIR, "umbral", "__about__.py")) as f:
    exec(f.read(), ABOUT)


with open(os.path.join(BASE_DIR, "README.rst")) as f:
    long_description = f.read()


TESTS_REQUIRE = [
    'pytest',
    'pytest-cov',
    'pytest-mypy',
    'pytest-mock',
    'mock',
    'coverage',
    'codecov',
    'monkeytype',
    ]

INSTALL_REQUIRES = ['msgpack-python',
                    'pynacl',
                    ]

EXTRAS_REQUIRE = {'testing': TESTS_REQUIRE,
                  'docs': ['sphinx', 'sphinx-autobuild'],
                  'benchmarks': ['pytest-benchmark'],
                  }


setup(name=ABOUT['__title__'],
      version=ABOUT['__version__'],
      author=ABOUT['__author__'],
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
        ]
      )
