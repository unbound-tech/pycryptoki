## Pypkcs11
[![Doc Status](https://readthedocs.org/projects/unbound-pypkcs11/badge/?version=latest)](http://unbound-pypkcs11.readthedocs.io/en/latest/)

Pypkcs11 is a python wrapper around the PKCS11 library.

## Documentation

The latest API documentation can be found on [readthedocs](http://unbound-pypkcs11.readthedocs.io).


## Key Generation Example

```py
from pypkcs11.default_templates import *
from pypkcs11.defines import *
from pypkcs11.key_generator import *
from pypkcs11.session_management import *
from pypkcs11.encryption import *

# NOTE: Return value checks are omitted for brevity
c_initialize()
ret, auth_session = c_open_session(0)   # slot # in this example is 0
login(auth_session, 0, 'userpin')  # 0 is still the slot number, ‘userpin’ should be replaced by your password (None if PED or no challenge)

# Get some default templates
# They are simple python dictionaries, and can be modified to suit needs.
pub_template, priv_template = get_default_key_pair_template(CKM_RSA_PKCS_KEY_PAIR_GEN)

# Modifying template would look like:
pub_template[CKA_LABEL] = "RSA PKCS Pub Key"
pub_template[CKA_MODULUS_BITS] = 2048   # 2048 key size

pubkey, privkey = c_generate_key_pair(auth_session, CKM_RSA_PKCS_KEY_PAIR_GEN, pub_template, priv_template)
print("Generated Private key at %s and Public key at %s" % (privkey, pubkey))

c_logout(auth_session)
c_close_session(auth_session)
c_finalize()
```
## Verbose Logging

If you want to see what calls to the C library are being performed, set pypkcs11 logging to `DEBUG`:

```py
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Tests

Test requirements can be installed via `pip install -r test_requirements.txt`.

Unit tests can be run on any environment via:
```
py.test tests/unittests
```

Functional tests require a UKC to test against, and actively test the integration
 with the libCryptoki library. These tests *will* create and destroy objects on the UKC, so don't run
  on a production UKC!

```
py.test tests/functional --slot=<slot_num> [--password=<pwd>] [--copassword=<pwd>] [--user=<user>] [--loglevel=<level>]
```
