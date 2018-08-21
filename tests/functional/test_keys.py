#
# Please note that this file has been modified by Unbound Tech
#
import logging

import pytest

from pypkcs11.default_templates import \
    (CKM_ECDSA_KEY_PAIR_GEN_PRIVTEMP, CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP,
     curve_list, get_default_key_template, get_default_key_pair_template,
     MECHANISM_LOOKUP_EXT, CKM_ECDH_KEY_PAIR_GEN_PUBTEMP,
     CKM_ECDH_KEY_PAIR_GEN_PRIVTEMP)
from pypkcs11.defines import *
from pypkcs11.encryption import c_encrypt, c_decrypt
from pypkcs11.key_generator import c_generate_key, c_generate_key_pair, c_derive_key, c_destroy_object
from pypkcs11.mechanism import NullMech
from pypkcs11.object_attr_lookup import c_get_attribute_value, c_find_objects
from pypkcs11.lookup_dicts import ret_vals_dictionary
from pypkcs11.test_functions import verify_object_attributes
from .util import get_session_template

logger = logging.getLogger(__name__)

KEYS = [CKM_DES3_KEY_GEN, CKM_AES_KEY_GEN]


def pair_params(key_gen):
    """ Return the params tuple given the key_gen mech """
    return (key_gen,) + get_default_key_pair_template(key_gen)


KEY_PAIRS = [pair_params(CKM_RSA_PKCS_KEY_PAIR_GEN),
             pair_params(CKM_ECDSA_KEY_PAIR_GEN)]

DERIVE_PARAMS = {
    CKM_SHA256_KEY_DERIVATION: "SHA256",
    CKM_SHA384_KEY_DERIVATION: "SHA384",
    CKM_SHA512_KEY_DERIVATION: "SHA512"}
DERIVE_KEYS = {CKM_DES3_KEY_GEN: "DES3",
               CKM_AES_KEY_GEN: "AES"}
DRV_TOO_LONG = {CKM_SHA1_KEY_DERIVATION: "SHA1"}
TOO_LONG_KEY = {CKM_DES3_KEY_GEN: "DES3",
                CKM_AES_KEY_GEN: "AES"
                }
ALL_DERIVES = {k: v for d in [DERIVE_PARAMS, DRV_TOO_LONG]
               for k, v in d.items()}

DATA = b"1234567812345678"


class TestKeys(object):
    """
    Tests Key & Key pair generation
    """

    def verify_ret(self, ret, expected_ret):
        """ Verify ret check and len > 0"""
        assert ret == expected_ret, "Function should return: " + ret_vals_dictionary[expected_ret] \
                                    + ".\nInstead returned: " + \
            ret_vals_dictionary[ret]

    def verify_key_len(self, k1, k2):
        """ Verify that key > 0"""
        assert k1 > 0, "Key should be > 0"
        assert k2 > 0, "Priv key should be > 0"

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.h_session = auth_session

    @pytest.mark.parametrize("key_type", KEYS, ids=[MECHANISM_LOOKUP_EXT[k][0] for k in KEYS])
    def test_generate_key(self, key_type, valid_mechanisms):
        """
        Test generation of keys for sym. crypto systems
        :param key_type: key generation mechanism
        """
        key_template = get_session_template(get_default_key_template(key_type))
        ret, key_handle = c_generate_key(
            self.h_session, key_type, key_template)

        try:
            if key_type not in valid_mechanisms:
                self.verify_ret(ret, CKR_MECHANISM_INVALID)
            else:
                self.verify_ret(ret, CKR_OK)
                self.verify_key_len(key_handle, key_handle)
        finally:
            c_destroy_object(self.h_session, key_handle)

    @pytest.mark.parametrize(("key_type", "pub_key_temp", "prv_key_temp"), KEY_PAIRS,
                             ids=[MECHANISM_LOOKUP_EXT[k[0]][0] for k in KEY_PAIRS])
    def test_generate_key_pair(self, key_type, pub_key_temp, prv_key_temp, valid_mechanisms):
        """
        Test generation of key pairs for asym. crypto systems
        :param key_type: key generation mechanism
        :param pub_key_temp: public key template
        :param prv_key_temp: private key template
        """
        ret, pub_key, prv_key = c_generate_key_pair(self.h_session, key_type,
                                                    get_session_template(
                                                        pub_key_temp),
                                                    get_session_template(prv_key_temp))
        try:
            if key_type not in valid_mechanisms:
                self.verify_ret(ret, CKR_MECHANISM_INVALID)
            else:
                self.verify_ret(ret, CKR_OK)
                self.verify_key_len(pub_key, prv_key)
        finally:
            c_destroy_object(self.h_session, prv_key)
            c_destroy_object(self.h_session, pub_key)

    @pytest.mark.parametrize("curve_type", list(curve_list.keys()))
    def test_generate_ecdsa_key_pairs(self, curve_type):
        """
        Test generate ECDSA key pairs
        :param curve_type:
        """
        pub_temp = CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP.copy()
        pub_temp[CKA_ECDSA_PARAMS] = curve_list[curve_type]
        data = c_generate_key_pair(self.h_session,
                                   CKM_ECDSA_KEY_PAIR_GEN,
                                   get_session_template(pub_temp),
                                   get_session_template(CKM_ECDSA_KEY_PAIR_GEN_PRIVTEMP))
        ret, public_key_handle, private_key_handle = data
        try:
            self.verify_ret(ret, CKR_OK)
            self.verify_key_len(public_key_handle, private_key_handle)
        finally:
            if public_key_handle:
                c_destroy_object(self.h_session, public_key_handle)
            if private_key_handle:
                c_destroy_object(self.h_session, private_key_handle)

    @pytest.mark.parametrize("d_type", list(DERIVE_PARAMS.keys()), ids=list(DERIVE_PARAMS.values()))
    @pytest.mark.parametrize("key_type", list(DERIVE_KEYS.keys()), ids=list(DERIVE_KEYS.values()))
    def test_derive_key(self, key_type, d_type, valid_mechanisms):
        """
        Test derive key for using parametrized hash
        :param key_type: Key-gen mechanism
        :param d_type: Hash mech
        """
        if key_type not in valid_mechanisms:
            pytest.skip("Not a valid mechanism on this product")
        key_template = get_session_template(get_default_key_template(key_type))
        ret, h_base_key = c_generate_key(
            self.h_session, key_type, key_template)
        self.verify_ret(ret, CKR_OK)
        mech = NullMech(d_type).to_c_mech()

        derived_key_template = key_template.copy()
        del derived_key_template[CKA_VALUE_LEN]

        ret, h_derived_key = c_derive_key(self.h_session, h_base_key,
                                          key_template,
                                          mechanism=mech)
        try:
            self.verify_ret(ret, CKR_OK)
            verify_object_attributes(
                self.h_session, h_derived_key, key_template)
        finally:
            if h_base_key:
                c_destroy_object(self.h_session, h_base_key)
            if h_derived_key:
                c_destroy_object(self.h_session, h_derived_key)

    @pytest.mark.parametrize("d_type", list(DRV_TOO_LONG.keys()), ids=list(DRV_TOO_LONG.values()))
    @pytest.mark.parametrize("key_type", list(TOO_LONG_KEY.keys()), ids=list(TOO_LONG_KEY.values()))
    def test_too_long_length_derives(self, key_type, d_type, valid_mechanisms):
        """
        Verify that trying to derive a key that is too long for the given derivation function
        will return CKR_KEY_SIZE_RANGE
        :param key_type:
        :param d_type:
        """
        if key_type not in valid_mechanisms:
            pytest.skip("Not a valid mechanism on this product")
        key_template = get_session_template(get_default_key_template(key_type))
        ret, h_base_key = c_generate_key(
            self.h_session, key_type, key_template)
        self.verify_ret(ret, CKR_OK)
        mech = NullMech(d_type).to_c_mech()

        derived_key_template = key_template.copy()
        del derived_key_template[CKA_VALUE_LEN]

        ret, h_derived_key = c_derive_key(self.h_session, h_base_key,
                                          key_template,
                                          mechanism=mech)
        try:
            self.verify_ret(ret, CKR_KEY_SIZE_RANGE)
        finally:
            if h_base_key:
                c_destroy_object(self.h_session, h_base_key)
            if h_derived_key:
                c_destroy_object(self.h_session, h_derived_key)

    @pytest.mark.parametrize("d_type", list(DERIVE_PARAMS.keys()), ids=list(DERIVE_PARAMS.values()))
    @pytest.mark.parametrize("key_type", list(TOO_LONG_KEY.keys()), ids=list(TOO_LONG_KEY.values()))
    def test_long_length_derive_key(self, key_type, d_type, valid_mechanisms):
        """
        Test deriving a key
        :param key_type: key generation mechanism
        :param d_type: derive mechanism
        """
        key_template = get_session_template(get_default_key_template(key_type))
        if key_type not in valid_mechanisms:
            pytest.skip("Not a valid mechanism on this product")
        ret, h_base_key = c_generate_key(
            self.h_session, key_type, key_template)
        mech = NullMech(d_type).to_c_mech()

        derived_key_template = key_template.copy()
        del derived_key_template[CKA_VALUE_LEN]

        ret, h_derived_key = c_derive_key(self.h_session,
                                          h_base_key,
                                          key_template,
                                          mechanism=mech)
        try:
            self.verify_ret(ret, CKR_OK)
            verify_object_attributes(
                self.h_session, h_derived_key, key_template)
        finally:
            if h_base_key:
                c_destroy_object(self.h_session, h_base_key)
            if h_derived_key:
                c_destroy_object(self.h_session, h_derived_key)

    @pytest.mark.parametrize("curve_type", sorted(list(curve_list.keys())))
    def test_x9_key_derive(self, auth_session, curve_type):
        """
        Test we can do X9 key derivation
        """
        derived_key2 = derived_key1 = pub_key1 = pub_key2 = prv_key2 = prv_key1 = None
        derived_template = {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_AES,
            CKA_ENCRYPT: True,
            CKA_DECRYPT: True,
            CKA_PRIVATE: True,
            CKA_SENSITIVE: True,
            CKA_VALUE_LEN: 16
        }
        pub_temp, priv_temp = (CKM_ECDH_KEY_PAIR_GEN_PUBTEMP,
                               CKM_ECDH_KEY_PAIR_GEN_PRIVTEMP)
        priv_temp = get_session_template(priv_temp)
        pub_temp = get_session_template(pub_temp)
        pub_temp[CKA_ECDSA_PARAMS] = curve_list[curve_type]

        ret, pub_key1, prv_key1 = c_generate_key_pair(auth_session,
                                                      CKM_ECDSA_KEY_PAIR_GEN,
                                                      pbkey_template=pub_temp,
                                                      prkey_template=priv_temp)
        self.verify_ret(ret, CKR_OK)
        try:
            ret, pub_key2, prv_key2 = c_generate_key_pair(auth_session,
                                                          CKM_ECDSA_KEY_PAIR_GEN,
                                                          pbkey_template=pub_temp,
                                                          prkey_template=priv_temp)
            self.verify_ret(ret, CKR_OK)
            ret, pub_key1_raw_ = c_get_attribute_value(auth_session,
                                                       pub_key1,
                                                       {CKA_EC_POINT: None})
            pub_key1_raw = pub_key1_raw_[CKA_EC_POINT]
            self.verify_ret(ret, CKR_OK)
            ret, pub_key2_raw_ = c_get_attribute_value(auth_session,
                                                       pub_key2,
                                                       {CKA_EC_POINT: None})
            pub_key2_raw = pub_key2_raw_[CKA_EC_POINT]
            self.verify_ret(ret, CKR_OK)
            ret, derived_key1 = c_derive_key(auth_session,
                                             h_base_key=prv_key2,
                                             template=derived_template,
                                             mechanism={"mech_type": CKM_ECDH1_DERIVE,
                                                        "params": {"kdf": CKD_NULL,
                                                                   "sharedData": None,
                                                                   "publicData": pub_key1_raw}})
            self.verify_ret(ret, CKR_OK)
            ret, derived_key2 = c_derive_key(auth_session,
                                             h_base_key=prv_key1,
                                             template=derived_template,
                                             mechanism={"mech_type": CKM_ECDH1_DERIVE,
                                                        "params": {"kdf": CKD_NULL,
                                                                   "sharedData": None,
                                                                   "publicData": pub_key2_raw}})
            self.verify_ret(ret, CKR_OK)
            ret, cipher_data = c_encrypt(auth_session,
                                         derived_key1,
                                         data=DATA,
                                         mechanism=CKM_AES_ECB)
            self.verify_ret(ret, CKR_OK)
            ret, restored_text = c_decrypt(auth_session,
                                           derived_key2,
                                           cipher_data,
                                           mechanism=CKM_AES_ECB)
            self.verify_ret(ret, CKR_OK)
            assert DATA == restored_text.rstrip(b'\x00')
        finally:
            for key in (pub_key1, prv_key1, pub_key2, prv_key2, derived_key1, derived_key2):
                if key:
                    c_destroy_object(auth_session, key)


if __name__ == '__main__':
    for k in KEY_PAIRS:
        mech = MECHANISM_LOOKUP_EXT[k[0]][0]
        print(mech)
