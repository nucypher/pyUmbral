from distutils.core import setup, Extension

INSTALL_REQUIRES = ['msgpack-python', 'cryptography', 'pynacl'] #'pysha3', 

TESTS_REQUIRE = [
    'pytest',
    'coverage',
    'pytest-cov',
    'pdbpp',
    'ipython'
]

setup(name='umbral',
      version='0.1',
      description='Umbral PRE implementation for NuCypher KMS',
      #ext_modules=[elliptic_curve],
      extras_require={'testing': TESTS_REQUIRE},
      install_requires=INSTALL_REQUIRES,
      packages=['umbral'])
