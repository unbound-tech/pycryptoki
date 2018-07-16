Examples
========


--------------------------
Generating an RSA Key Pair
--------------------------

This example creates a 1024b RSA Key Pair.


   .. code-block:: python

       from pypkcs11.session_management import (c_initialize_ex, c_finalize_ex,
                                                  c_open_session_ex, c_close_session_ex,
                                                  login_ex)
       from pypkcs11.defines import CKM_RSA_PKCS_KEY_PAIR_GEN
       from pypkcs11.key_generator import c_generate_key_pair_ex

        # NOTE: Return value checks are omitted for brevity
       c_initialize()
       ret, session = c_open_session(0)      # 0 -> slot number
       login(session, 0, 'userpin')     # 0 -> Slot number, 'userpin' -> token password

       # Templates are dictionaries in pypkcs11
       pub_template = {CKA_TOKEN: True,
                       CKA_PRIVATE: True,
                       CKA_MODIFIABLE: True,
                       CKA_ENCRYPT: True,
                       CKA_VERIFY: True,
                       CKA_WRAP: True,
                       CKA_MODULUS_BITS: 1024,  # long 0 - MAX_RSA_KEY_NBITS
                       CKA_PUBLIC_EXPONENT: 3,  # byte
                       CKA_LABEL: b"RSA Public Key"}
       priv_template = {CKA_TOKEN: True,
                        CKA_PRIVATE: True,
                        CKA_SENSITIVE: True,
                        CKA_MODIFIABLE: True,
                        CKA_EXTRACTABLE: True,
                        CKA_DECRYPT: True,
                        CKA_SIGN: True,
                        CKA_UNWRAP: True,
                        CKA_LABEL: b"RSA Private Key"}

       ret, pub_key, priv_key = c_generate_key_pair(session,
                                                mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN,
                                                pbkey_template=pub_template,
                                                prkey_template=priv_template)

       c_close_session(session)
       c_finalize()


--------------------------------
Encrypting data with AES-256-GCM
--------------------------------

This example generates a 32-byte AES key, then encrypts some data
with that key using the AES-GCM mechanism.

   .. code-block:: python


       from pypkcs11.session_management import (c_initialize, c_finalize,
                                                  c_open_session, c_close_session,
                                                  login)
       from pypkcs11.defines import (CKM_AES_KEY_GEN,
                                       CKA_LABEL,
                                       CKA_ENCRYPT,
                                       CKA_DECRYPT,
                                       CKA_TOKEN,
                                       CKA_CLASS,
                                       CKA_KEY_TYPE,
                                       CKK_AES,
                                       CKO_SECRET_KEY,
                                       CKA_SENSITIVE,
                                       CKA_WRAP,
                                       CKA_UNWRAP,
                                       CKA_DERIVE,
                                       CKA_VALUE_LEN,
                                       CKA_EXTRACTABLE,
                                       CKA_PRIVATE,
                                       CKM_AES_GCM)
       from pypkcs11.key_generator import c_generate_key
       from pypkcs11.encryption import c_encrypt
       from pypkcs11.conversions import to_bytestring, from_hex
       from pypkcs11.mechanism import Mechanism

        # NOTE: Return value checks are omitted for brevity
       c_initialize()
       ret, session = c_open_session(0)      # 0 = slot number
       login(session, 0, 'userpin')        # 'userpin' = token password


       template = {CKA_LABEL: b"Sample AES Key",
                   CKA_ENCRYPT: True,
                   CKA_DECRYPT: True,
                   CKA_TOKEN: False,
                   CKA_CLASS: CKO_SECRET_KEY,
                   CKA_KEY_TYPE: CKK_AES,
                   CKA_SENSITIVE: True,
                   CKA_PRIVATE: True,
                   CKA_WRAP: True,
                   CKA_UNWRAP: True,
                   CKA_DERIVE: True,
                   CKA_VALUE_LEN: 32,
                   CKA_EXTRACTABLE: True,}
       ret, aes_key = c_generate_key(session, CKM_AES_KEY_GEN, template)

       # Data is in hex format here
       raw_data = "d0d77c63ab61e75a5fd4719fa77cc2de1d817efedcbd43e7663736007672e8c7"

       # Convert to raw bytes before passing into c_encrypt:
       data_to_encrypt = to_bytestring(from_hex(raw_data))


       # Note: static IV is provided for simplicity; use random IVs instead
       mechanism = Mechanism(mech_type=CKM_AES_GCM,
                             params={"iv": list(range(16)), 'AAD': b'deadbeef', 'ulTagBits': 32})

       ret, static_iv_encrypted_data = c_encrypt(session, aes_key, data_to_encrypt, mechanism)

       c_close_session(session)
       c_finalize()


---------------------------------
Finding a key and decrypting Data
---------------------------------

This example follows from the previous one, except instead of generating a key,
we'll find one that was already used.


.. code-block:: python

       from pypkcs11.session_management import (c_initialize_ex, c_finalize_ex,
                                                  c_open_session_ex, c_close_session_ex,
                                                  login_ex)
       from pypkcs11.object_attr_lookup import c_find_objects_ex
       from pypkcs11.defines import (CKM_AES_KEY_GEN,
                                       CKA_LABEL,
                                       CKA_ENCRYPT,
                                       CKA_DECRYPT,
                                       CKA_TOKEN,
                                       CKA_CLASS,
                                       CKA_KEY_TYPE,
                                       CKK_AES,
                                       CKO_SECRET_KEY,
                                       CKA_SENSITIVE,
                                       CKA_WRAP,
                                       CKA_UNWRAP,
                                       CKA_DERIVE,
                                       CKA_VALUE_LEN,
                                       CKA_EXTRACTABLE,
                                       CKA_PRIVATE,
                                       CKM_AES_GCM)
       from pypkcs11.encryption import c_decrypt
       from pypkcs11.conversions import to_bytestring, from_hex
       from pypkcs11.mechanism import Mechanism

       c_initialize()
       ret, session = c_open_session(0)      # 0 = slot number
       login(session, 0, 'userpin')        # 'userpin' = token password

       template = {CKA_LABEL: b"Sample AES key"}

       keys = c_find_objects(session, template, 1)
       aes_key = keys.pop(0) # Use the first key found.

       # Data is in hex format here
       raw_data = "95e28bc6da451f3064d688dd283c5c43a5dd374cb21064df836e2970e1024c2448f129062aacbae3e45abd098b893346"

       # Convert to raw bytes before passing into c_decrypt:
       data_to_decrypt = to_bytestring(from_hex(raw_data))


       # Note: static IV is provided for simplicity; use random IVs instead
       mechanism = Mechanism(mech_type=CKM_AES_GCM,
                             params={"iv": list(range(16)), 'AAD': b'deadbeef', 'ulTagBits': 32})
       ret, original_data = c_decrypt(session, aes_key, data_to_decrypt, mechanism)

       c_close_session(session)
       c_finalize()

.. footer:: Please note that this document have been modified by Unbound Tech.

