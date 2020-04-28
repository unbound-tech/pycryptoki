# *
# * Copyright 2018 Unbound Tech Ltd.

# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.

# * You may obtain a copy of the License at
# * http://www.apache.org/licenses/LICENSE-2.0


# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License
# *

"""
Testcases for Unbound Tech functions.
"""
import pytest
import binascii
import uuid

from pypkcs11.key_generator import c_generate_key_pair, c_destroy_object, c_derive_key
from pypkcs11.defines import *
from pypkcs11.unbound import dyc_self_sign_x509, dyc_sign_x509, dyc_create_x509_request
from pypkcs11.default_templates import CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP, CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP
from pypkcs11.default_templates import DYCKM_EDDSA_KEY_GEN, EDDSA_KEY_GEN_PUBTEMP, EDDSA_KEY_GEN_PRIVTEMP
from pypkcs11.misc import c_create_object
from pypkcs11.object_attr_lookup import c_get_attribute_value
from pypkcs11.mechanism.unbound import EcdsaBipDeriveMechanism
from pypkcs11.sign_verify import c_sign, c_verify
from pypkcs11.default_templates import CURVE_SECP256K1


class TestUnbound(object):

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.h_session = auth_session

    def test_sign_x509(self):

        ret, pub_key, priv_key = c_generate_key_pair(self.h_session,
                                                     mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN,
                                                     pbkey_template=CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP,
                                                     prkey_template=CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP)
        assert ret == CKR_OK
        ret, pub_key2, priv_key2 = c_generate_key_pair(self.h_session,
                                                       mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN,
                                                       pbkey_template=CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP,
                                                       prkey_template=CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP)
        assert ret == CKR_OK
        try:
            mechanism = CKM_RSA_X_509
            ret, x509CA = dyc_self_sign_x509(self.h_session, priv_key, CKM_SHA256,
                                             'CN=some guy, L=around, C=US', None, 365)
            assert ret == CKR_OK

            ret, csr = dyc_create_x509_request(
                self.h_session, priv_key2, CKM_SHA256, 'CN=some guy, L=around, C=US')
            assert ret == CKR_OK

            ret, x509 = dyc_sign_x509(
                self.h_session, priv_key, x509CA, CKM_SHA256, csr)
            assert ret == CKR_OK
        finally:
            if pub_key is not None:
                c_destroy_object(self.h_session, pub_key)
            if priv_key is not None:
                c_destroy_object(self.h_session, priv_key)
            if pub_key2 is not None:
                c_destroy_object(self.h_session, pub_key2)
            if priv_key2 is not None:
                c_destroy_object(self.h_session, priv_key2)

    def test_bip(self):
        seed = uuid.uuid4().hex
        t_new_seed_key = {CKA_CLASS: CKO_SECRET_KEY,
                          CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                          CKA_TOKEN: True,
                          CKA_DERIVE: True,
                          CKA_VALUE: binascii.unhexlify(seed),
                          }
        ret, hSeed = c_create_object(self.h_session, t_new_seed_key)
        assert ret == CKR_OK
        hBip, hBipDer = None, None
        try:
            t_new_ec_key = {CKA_CLASS: CKO_PRIVATE_KEY,
                            CKA_KEY_TYPE: CKK_EC,
                            CKA_TOKEN: True,
                            CKA_EC_PARAMS: CURVE_SECP256K1,
                            CKA_SIGN: True,
                            CKA_DERIVE: True,
                            }
            ret, hBip = c_derive_key(
                self.h_session, hSeed, t_new_ec_key, DYCKM_DERIVE_ECDSA_BIP)
            assert ret == CKR_OK

            t_info = {DYCKA_ECDSA_BIP_LEVEL: None,
                      DYCKA_ECDSA_BIP_CHILD_NUMBER: None,
                      DYCKA_ECDSA_BIP_PARENT_FINGERPRINT: None,
                      DYCKA_ECDSA_BIP_CPAR: None,
                      DYCKA_ECDSA_BIP_HARDENED: None,
                      }
            ret, attrs = c_get_attribute_value(self.h_session, hBip, t_info)
            assert ret == CKR_OK

            bip_mech = EcdsaBipDeriveMechanism(True, 0)
            ret, hBipDer = c_derive_key(
                self.h_session, hBip, t_new_ec_key, bip_mech)
            assert ret == CKR_OK
            ret, attrs = c_get_attribute_value(self.h_session, hBipDer, t_info)
            assert ret == CKR_OK

        finally:
            if hSeed is not None:
                c_destroy_object(self.h_session, hSeed)
            if hBip is not None:
                c_destroy_object(self.h_session, hBip)
            if hBipDer is not None:
                c_destroy_object(self.h_session, hBipDer)

    def test_eddsa(self):
        data = b"This is some test string to sign."
        ret, pub_key, priv_key = c_generate_key_pair(self.h_session,
                                                     mechanism=DYCKM_EDDSA_KEY_GEN,
                                                     pbkey_template=EDDSA_KEY_GEN_PUBTEMP,
                                                     prkey_template=EDDSA_KEY_GEN_PRIVTEMP)

        assert ret == CKR_OK
        ret, signature = c_sign(self.h_session, priv_key,
                                data,  mechanism=DYCKM_EDDSA)
        assert ret == CKR_OK

        ret = c_verify(self.h_session, pub_key, data,
                       signature, mechanism=DYCKM_EDDSA)
        assert ret == CKR_OK
