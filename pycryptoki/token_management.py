"""
Created on Aug 24, 2012

@author: mhughes
"""
import logging
from ctypes import byref

from .cryptoki import (CK_ULONG,
                       CK_BBOOL,
                       CK_MECHANISM_TYPE,
                       CK_MECHANISM_INFO)
from .defines import CKR_OK

# Cryptoki functions.
from .cryptoki import (C_InitToken,
                       C_GetSlotList,
                       C_GetMechanismList,
                       C_GetMechanismInfo,
                       )
from .session_management import c_get_token_info
from .common_utils import AutoCArray
from .common_utils import refresh_c_arrays

LOG = logging.getLogger(__name__)


def c_init_token(slot_num, password, token_label='Main Token'):
    """Initializes at token at a given slot with the proper password and label

    :param slot_num: The index of the slot to c_initialize a token in
    :param password: The password to c_initialize the slot with
    :param token_label: The label to c_initialize the slot with (Default value = 'Main Token')
    :returns: The result code

    """
    LOG.info("C_InitToken: Initializing token (slot=%s, label='%s', password='%s')",
             slot_num, token_label, password)

    if password == b'':
        password = None
    password = AutoCArray(data=password)
    slot_id = CK_ULONG(slot_num)
    label = AutoCArray(data=token_label)

    return C_InitToken(slot_id,
                       password.array, password.size.contents,
                       label.array)


def get_token_by_label(label):
    """Iterates through all the tokens and returns the first token that
    has a label that is identical to the one that is passed in

    :param label: The label of the token to search for
    :returns: The result code, The slot of the token

    """

    slot_list = AutoCArray()

    @refresh_c_arrays(1)
    def _get_slot_list():
        """Closure
        """
        return C_GetSlotList(CK_BBOOL(1), slot_list.array, slot_list.size)

    ret = _get_slot_list()
    if ret != CKR_OK:
        return ret, None

    for slot in slot_list:
        ret, token_info = c_get_token_info(slot)
        if token_info['label'] == label:
            return ret, slot

    raise Exception("Slot with label " + str(label) + " not found.")


def c_get_mechanism_list(slot):
    """Gets the list of mechanisms 

    :param slot: The slot number to get the mechanism list on
    :returns: The result code, A python dictionary representing the mechanism list

    """
    slot_id = CK_ULONG(slot)
    mech = AutoCArray(ctype=CK_MECHANISM_TYPE)

    @refresh_c_arrays(1)
    def _c_get_mech_list():
        """Closure for retry to work w/ properties.
        """
        return C_GetMechanismList(slot_id, mech.array, mech.size)

    ret = _c_get_mech_list()
    return ret, [x for x in mech]


def c_get_mechanism_info(slot, mechanism_type):
    """Gets a mechanism's info

    :param slot: The slot to query
    :param mechanism_type: The type of the mechanism to get the information for
    :returns: The result code, The mechanism info

    """
    mech_info = CK_MECHANISM_INFO()
    ret = C_GetMechanismInfo(CK_ULONG(slot), CK_MECHANISM_TYPE(mechanism_type), byref(mech_info))
    return ret, mech_info

