"""
Script used by distutils to automatically generate a source code
distribution of this python module (a .tar.gz file containing
all of the source code).

To generate this file run:
python setup.py sdist
"""
from setuptools import setup

setup(name='unbound-pkcs11',
      description="A python wrapper around the PKCS#11 C library.",
      maintainer='Michael Kraitsberg',
      url='https://github.com/unbound-tech/pycryptoki',
      version='2.1.1',
      packages=['pycryptoki',
                'pycryptoki.mechanism'],
      tests_require=['pytest', 'hypothesis', 'mock', 'pytz'],
      install_requires=['six']
      )
