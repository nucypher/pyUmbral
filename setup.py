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

from distutils.core import setup

from cffi.setuptools_ext import execfile

execfile(filename='./__version__.py', glob="__version__")

INSTALL_REQUIRES = ['msgpack-python', 'pynacl']

TESTS_REQUIRE = [
    'pytest',
    'coverage',
    'pytest-cov',
    'pdbpp',
    'ipython'
]

setup(name='umbral',
      version='0.1.0-alpha',
      description='Umbral PRE implementation for NuCypher',
      extras_require={'testing': TESTS_REQUIRE},
      install_requires=INSTALL_REQUIRES,
      packages=['umbral'])
