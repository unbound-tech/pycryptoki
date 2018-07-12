#
# Please note that this file has been modified by Unbound Tech
#
""" Functional tests for signature / verification"""
import logging
import pytest

from pypkcs11.sign_verify import c_sign, c_verify
from pypkcs11.key_generator import c_generate_key_pair, c_generate_key, c_destroy_object
from pypkcs11.defines import (CKM_AES_GMAC, CKM_AES_CMAC, CKM_AES_KEY_GEN,
                              CKM_DES3_MAC, CKM_DES3_CMAC, CKM_DES3_KEY_GEN,
                              CKM_ECDSA_SHA1, CKM_ECDSA_KEY_PAIR_GEN,
                              CKR_OK)
from pypkcs11.default_templates import (
    CKM_ECDSA_KEY_PAIR_GEN_PRIVTEMP,
    CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP,

    MECHANISM_LOOKUP_EXT, get_default_key_template)

from pypkcs11.lookup_dicts import ret_vals_dictionary
from .util import get_session_template

logger = logging.getLogger(__name__)

DATA = [b"This is some test string to sign.", [b"a" * 1024, b"b" * 1024]]

SYM_PARAMS = [(CKM_AES_KEY_GEN, CKM_AES_CMAC),
              #(CKM_AES_KEY_GEN, CKM_AES_GMAC),
              #   (CKM_DES3_KEY_GEN, CKM_DES3_MAC),
              (CKM_DES3_KEY_GEN, CKM_DES3_CMAC),
              #   (CKM_CAST3_KEY_GEN, CKM_CAST3_MAC),
              #   (CKM_CAST5_KEY_GEN, CKM_CAST5_MAC),
              ]
SYM_KEYS = [key for key, _ in SYM_PARAMS]

ASYM_PARAMS = \
    [(CKM_ECDSA_KEY_PAIR_GEN, CKM_ECDSA_KEY_PAIR_GEN_PUBTEMP,
      CKM_ECDSA_KEY_PAIR_GEN_PRIVTEMP, CKM_ECDSA_SHA1)]

FORMAT_ASYM = [(key, sig) for (key, _, _, sig) in ASYM_PARAMS]


def idfn(params):
    """ Generate test ids """
    id_list = []
    for s in params:
        id_list.append(MECHANISM_LOOKUP_EXT[s[0]][0].
                       replace("CKM_", "").replace("_KEY_PAIR_GEN", "").replace("_KEY_GEN", ""))
    return id_list


@pytest.yield_fixture(scope='class')
def sym_keys(auth_session):
    """ Fixture containing all sym. keys """
    keys = {}
    try:
        for key_type in SYM_KEYS:
            template = get_session_template(get_default_key_template(key_type))
            ret, key_handle = c_generate_key(auth_session, key_type, template)
            if ret == CKR_OK:
                keys[key_type] = key_handle
            else:
                logger.info(
                    "Failed to generate key: {}\nReturn code: {}".format(key_type, ret))
        yield keys

    finally:
        for handle in keys.values():
            c_destroy_object(auth_session, handle)


@pytest.yield_fixture(scope='class')
def asym_keys(auth_session):
    """ Fixture containing all asym. keys """
    keys = {}
    try:
        for params in ASYM_PARAMS:
            key_type, pub_temp, prv_temp, _ = params
            ret, pub_key, prv_key = c_generate_key_pair(auth_session,
                                                        key_type,
                                                        get_session_template(
                                                            pub_temp),
                                                        get_session_template(prv_temp))
            if ret == CKR_OK:
                keys[key_type] = (pub_key, prv_key)
            else:
                logger.info(
                    "Failed to generate key: {}\nReturn code: {}".format(key_type, ret))
        yield keys

    finally:
        for pub_key, prv_key in keys.values():
            c_destroy_object(auth_session, pub_key)
            c_destroy_object(auth_session, prv_key)


class TestSignVerify(object):
    """
    Creates key pairs, signs data, and verifies that data.
    """

    def verify_ret(self, ret, expected_ret):
        """
        Assert that ret is as expected
        :param ret: the actual return value
        :param expected_ret: the expected return value
        """
        assert ret == expected_ret, "Function should return: " + \
                                    ret_vals_dictionary[expected_ret] + ".\nInstead returned: " + \
                                    ret_vals_dictionary[ret]

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.h_session = auth_session

    @pytest.mark.parametrize("data", DATA, ids=['String', 'Block'])
    @pytest.mark.parametrize(('key_type', 'sign_flavor'), SYM_PARAMS, ids=idfn(SYM_PARAMS))
    def test_sym_sign_verify(self, key_type, sign_flavor, data, sym_keys):
        """
        Test sym. sign / verify
        :param key_type: key_gen type
        :param sign_flavor: signature mech
        :param data: testing data
        :param sym_keys: key fixture
        """
        # Auto-fail when key-generation fails
        if sym_keys.get(key_type) is None:
            pytest.skip("No valid key found for {}".format(
                MECHANISM_LOOKUP_EXT[key_type][0]))
        h_key = sym_keys[key_type]

        ret, signature = c_sign(self.h_session, h_key,
                                data,  mechanism=sign_flavor)
        self.verify_ret(ret, CKR_OK)

        ret = c_verify(self.h_session, h_key, data,
                       signature, mechanism=sign_flavor)
        self.verify_ret(ret, CKR_OK)

    @pytest.mark.parametrize("data", DATA, ids=['String', "Block"])
    @pytest.mark.parametrize(("k_type", "sig_mech"), FORMAT_ASYM, ids=idfn(ASYM_PARAMS))
    def test_asym_sign_verify(self, k_type, sig_mech, data, asym_keys):
        """
        Test asym. sign / verify
        :param k_type: key_gen type
        :param sig_mech: signature mech
        :param data: testing data
        :param asym_keys: key fixture
        """
        # Auto-fail when key-generation fails
        if asym_keys.get(k_type) is None:
            pytest.skip("No valid key found for {}".format(
                MECHANISM_LOOKUP_EXT[k_type][0]))
        pub_key, prv_key = asym_keys[k_type]

        ret, signature = c_sign(self.h_session, prv_key,
                                data, mechanism=sig_mech)
        self.verify_ret(ret, CKR_OK)

        ret = c_verify(self.h_session, pub_key, data,
                       signature, mechanism=sig_mech)
        self.verify_ret(ret, CKR_OK)
