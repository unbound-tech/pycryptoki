#
# Please note that this file have been modified by Unbound Tech
#
"""
Testcases for object creation
"""

import logging

import pytest
from pypkcs11.key_generator import c_destroy_object

from pypkcs11.defines import CKA_VALUE, CKR_OK

from pypkcs11.object_attr_lookup import c_get_attribute_value

from pypkcs11.default_templates import CERTIFICATE_TEMPLATE, DATA_TEMPLATE
from pypkcs11.misc import c_create_object
from . import config as test_config
from .util import get_session_template

logger = logging.getLogger(__name__)


class TestObjectCreation(object):
    """Tests certificate & data creation."""

    @pytest.fixture(autouse=True)
    def setup_teardown(self, auth_session):
        self.h_session = auth_session
        self.admin_slot = test_config["test_slot"]

    def test_certificate_create(self):
        """Tests C_CreateObject with a certificate template and verifies the object's
        attributes


        """
        template = get_session_template(CERTIFICATE_TEMPLATE)
        ret, h_object = c_create_object(self.h_session, template)
        assert ret == CKR_OK
        try:
            desired_attrs = {x: None for x in template.keys()}
            ret, attr = c_get_attribute_value(self.h_session, h_object, template=desired_attrs)
            assert ret == CKR_OK
            # CKA_VALUE in the template is a list of ints, but is returned as a single hex string.
            # Let's try to convert it back to the list of ints.
            value = attr[CKA_VALUE]
            attr[CKA_VALUE] = [int(value[x:x+2], 16) for x in range(0, len(value), 2)]
            assert attr == template
        finally:
            c_destroy_object(self.h_session, h_object)

    def test_data_create(self):
        """Tests C_CreateObject with a data template and verifies the object's
        attributes


        """
        template = get_session_template(DATA_TEMPLATE)
        ret, h_object = c_create_object(self.h_session, template)
        assert ret == CKR_OK
        try:
            desired_attrs = {x: None for x in template.keys()}
            ret, attr = c_get_attribute_value(self.h_session, h_object, template=desired_attrs)
            assert ret == CKR_OK
            # CKA_VALUE in the template is a list of ints, but is returned as a single hex string.
            # Let's try to convert it back to the list of ints.
            value = attr[CKA_VALUE]
            attr[CKA_VALUE] = [int(value[x:x + 2], 16) for x in range(0, len(value), 2)]
            assert attr == template
        finally:
            c_destroy_object(self.h_session, h_object)

if __name__ == '__main__':
    test_library()
