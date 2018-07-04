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
import os
import pytest

from pypkcs11.key_generator import c_generate_key_pair, c_destroy_object
from pypkcs11.defines import *
from pypkcs11.unbound import dyc_self_sign_x509, dyc_sign_x509
from pypkcs11.default_templates import CKM_RSA_PKCS_KEY_PAIR_GEN_PUBTEMP, CKM_RSA_PKCS_KEY_PAIR_GEN_PRIVTEMP

def _get_data_file(filename):
    """
    Get absolute path to filename. Uses current directory as basis to find the testdata folder.

    :param str filename: Filename to append
    :return: full path to file
    """
    return os.path.join(os.path.split(os.path.abspath(__file__))[0], "testdata", filename)

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
        try:
            mechanism = CKM_RSA_X_509
            ret, x509CA = dyc_self_sign_x509(self.h_session, priv_key, CKM_SHA256,
                                            'CN=some guy, L=around, C=US', None, 365)
            assert ret == CKR_OK

            with open(_get_data_file('test_csr.der'), mode='rb') as file:
                csr = file.read()

            ret, x509 = dyc_sign_x509(self.h_session, priv_key, x509CA, CKM_SHA256, csr)
            assert ret == CKR_OK
        finally:
            if (pub_key != None):
                c_destroy_object(self.h_session, pub_key)
            if (priv_key != None):
                c_destroy_object(self.h_session, priv_key)

