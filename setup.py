#
# Please note that this file has been modified by Unbound Tech
#
"""
Script used by distutils to automatically generate a source code
distribution of this python module (a .tar.gz file containing
all of the source code).

To generate this file run:
python setup.py sdist
"""
from setuptools import setup
import os

thelibFolder = os.path.dirname(os.path.realpath(__file__))
requirementPath = thelibFolder + '/requirements.txt'
install_requires = [] 
if os.path.isfile(requirementPath):
    with open(requirementPath) as f:
        install_requires = [line for line in f.read().splitlines() if len(line) > 0 and line[0] != '#']

testRequirementPath = thelibFolder + '/test_requirements.txt'
tests_require = [] 
if os.path.isfile(testRequirementPath):
    with open(requirementPath) as f:
        tests_require = [line for line in f.read().splitlines() if len(line) > 0 and line[0] != '#']
		
setup(name='unbound-pkcs11',
      description="A python wrapper around the PKCS#11 C library.",
      maintainer='Michael Kraitsberg',
      url='https://github.com/unbound-tech/unbound-pypkcs11',
      version='1.0.0',
      packages=['pypkcs11',
                'pypkcs11.mechanism'],
      tests_require=tests_require,
      install_requires=install_requires
      )
