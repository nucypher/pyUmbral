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

base_dir = os.path.dirname(__file__)
src_dir = os.path.join(base_dir, "src")

about = {}
with open(os.path.join(src_dir, "umbral", "__about__.py")) as f:
    exec(f.read(), about)

INSTALL_REQUIRES = ['msgpack-python', 'pynacl']

TESTS_REQUIRE = [
    'pytest',
    'coverage',
    'pytest-cov',
    'pdbpp',
    'ipython'
]


setup(name=about['__title__'],
      version=about['__version__'],
      author=about['__author'],
      description=about["__summary__"],
      long_description_markdown_filename='README.md',
      extras_require={'testing': TESTS_REQUIRE},
      install_requires=INSTALL_REQUIRES,
      packages=['umbral'],
      classifiers=[
          "Natural Language :: English",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: 3.7",
        ]
      )
