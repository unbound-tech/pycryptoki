Pypkcs11
==========


Overview
--------

Pypkcs11 is an open-source Python wrapper around PKCS#11 C library. Using python's ctypes library,
we can simplify memory management, and provide easy, pythonic access to a PKCS11 shared library.

The primary function of pypkcs11 is to *simplify* PKCS11 calls. Rather than needing to calculate
data sizes, buffers, or other low-level memory manipulation, you simply need to pass in data.

It's highly recommended that you have the `PKCS11 <https://www.cryptsoft.com/pkcs11doc/v220/>`_ documentation
handy, as pypkcs11 uses that as the underlying C interface. Session management, object management,
and other concepts are unchanged from PKCS11.

.. code-block:: python

   from pypkcs11.default_templates import *
   from pypkcs11.defines import *
   from pypkcs11.key_generator import *
   from pypkcs11.session_management import *


   c_initialize()
    # NOTE: Return value checks are omitted for brevity
   ret, auth_session = c_open_session(0)   # slot # in this example is 0
   login(auth_session, 0, 'userpin')  # 0 is still the slot number, ‘userpin’ should be replaced by your password (None if PED or no challenge)

   # Get some default templates
   # They are simple python dictionaries, and can be modified to suit needs.
   ret, pub_template, priv_template = get_default_key_pair_template(CKM_RSA_PKCS_KEY_PAIR_GEN)

   # Modifying template would look like:
   pub_template[CKA_LABEL] = b"RSA PKCS Pub Key"
   pub_template[CKA_MODULUS_BITS] = 2048   # 2048 key size

   ret, pubkey, privkey = c_generate_key_pair(auth_session, CKM_RSA_PKCS_KEY_PAIR_GEN, pub_template, priv_template)
   print("Generated Private key at %s and Public key at %s" % (privkey, pubkey))

   c_logout(auth_session)
   c_close_session(auth_session)
   c_finalize()



.. toctree::
   :maxdepth: 4
   :includehidden:

   Getting Started      <getting_started>
   Examples             <examples>
   Frequent Issues      <problems>
   API Reference        <api>

.. footer:: Please note that this document have been modified by Unbound Tech.

