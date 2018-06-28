#
# Please note that this file have been modified by Unbound Tech
#
"""
Methods responsible for managing a user's session and login/c_logout
"""
import logging
from ctypes import cast, c_void_p, create_string_buffer, \
    byref, pointer, string_at

from .common_utils import AutoCArray
# cryptoki constants
from .cryptoki import (CK_ULONG,
                       CK_BBOOL,
                       CK_SLOT_ID,
                       CK_SLOT_INFO,
                       CK_SESSION_HANDLE,
                       CK_FLAGS,
                       CK_NOTIFY,
                       CK_SESSION_INFO,
                       CK_USER_TYPE,
                       CK_TOKEN_INFO,
                       CK_VOID_PTR,
                       CK_BYTE, CK_INFO, C_GetInfo, c_ulong)
# Cryptoki Functions
from .cryptoki import (C_Initialize,
                       C_GetSlotList,
                       C_GetSlotInfo,
                       C_CloseAllSessions,
                       C_GetSessionInfo,
                       C_OpenSession,
                       C_Login,
                       C_Logout,
                       C_CloseSession,
                       C_InitPIN,
                       C_GetTokenInfo,
                       C_Finalize,
                       C_SetPIN,
                        )
from .defines import CKR_OK, CKF_RW_SESSION, CKF_SERIAL_SESSION

LOG = logging.getLogger(__name__)


def c_initialize():
    """Initializes current process for use with PKCS11

    :returns: retcode
    """
    # INITIALIZE
    LOG.info("C_Initialize: Initializing library")
    ret = C_Initialize(0)
    return ret


def c_finalize():
    """Finalizes PKCS11 usage.

    :return: retcode
    """

    LOG.info("C_Finalize: Finalizing library")
    ret = C_Finalize(0)
    return ret


def c_open_session(slot_num, flags=(CKF_SERIAL_SESSION | CKF_RW_SESSION)):
    """Opens a session on the given slot

    :param int slot_num: The slot to get a session on
    :param int flags: The flags to open the session with
        (Default value = (CKF_SERIAL_SESSION | CKF_RW_SESSION)
    :returns: (retcode, session handle)
    :rtype: tuple
    """
    # OPEN SESSION
    arg3 = create_string_buffer(b"Application")
    h_session = CK_SESSION_HANDLE()
    arg3 = cast(arg3, c_void_p)
    # CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR)
    ret = C_OpenSession(CK_SLOT_ID(slot_num), CK_FLAGS(flags),
                        cast(arg3, CK_VOID_PTR), CK_NOTIFY(0),
                        pointer(h_session))
    LOG.info("C_OpenSession: Opening Session. slot=%s", slot_num)

    return ret, h_session.value


def login(h_session, slot_num=1, password=None, user_type=1):
    """Login to the given session.

    :param int h_session: Session handle
    :param int slot_num: Slot index to login on (Default value = 1)
    :param bytes password: Password to login with (Default value = "userpin")
    :param int user_type: User type to login as (Default value = 1)
    :returns: retcode
    :rtype: int
    """
    # LOGIN
    LOG.info("C_Login: "
             "user_type=%s, "
             "slot=%s, "
             "password=***", user_type, slot_num)
    if password == '':
        password = None

    user_type = CK_USER_TYPE(user_type)
    password = AutoCArray(data=password, ctype=CK_BYTE)

    ret = C_Login(h_session, user_type, password.array, password.size.contents)

    return ret


def c_get_info():
    """
    Get general information about the Cryptoki Library

    Returns a dictionary containing the following keys:

        * cryptokiVersion
        * manufacturerID
        * flags
        * libraryDescription
        * libraryVersion

    ``cryptokiVersion`` and ``libraryVersion`` are :ref:`~pypkcs11.cryptoki.CK_VERSION` structs,
    and the major/minor values can be accessed directly (``info['cryptokiVersion'].major == 2``)

    :return: (retcode, info dictionary)
    """
    info = {}
    info_struct = CK_INFO()
    ret = C_GetInfo(byref(info_struct))
    if ret == CKR_OK:
        info['cryptokiVersion'] = info_struct.cryptokiVersion
        info['manufacturerID'] = string_at(info_struct.manufacturerID)
        info['flags'] = info_struct.flags
        info['libraryDescription'] = string_at(info_struct.libraryDescription)
        info['libraryVersion'] = info_struct.libraryVersion
    return ret, info


def c_get_slot_list(token_present=True):
    """
    Get a list of all slots.

    :param bool token_present: If true, will only return slots that have a token present.
    :return: List of slots
    """
    slots = AutoCArray(ctype=CK_ULONG)

    rc = C_GetSlotList(CK_BBOOL(token_present),
                       slots.array,
                       slots.size)
    if rc != CKR_OK:
        return rc, []
    rc = C_GetSlotList(CK_BBOOL(token_present),
                       slots.array,
                       slots.size)
    return rc, [x for x in slots]


def c_get_slot_info(slot):
    """
    Get information about the given slot number.

    :param int slot: Target slot
    :return: Dictionary of slot information
    """
    slot_info = CK_SLOT_INFO()
    slot_info_dict = {}
    ret = C_GetSlotInfo(slot, byref(slot_info))
    if ret != CKR_OK:
        return ret, {}

    slot_info_dict['slotDescription'] = string_at(slot_info.slotDescription, 64).rstrip()
    slot_info_dict['manufacturerID'] = string_at(slot_info.manufacturerID, 32).rstrip()
    slot_info_dict['flags'] = slot_info.flags
    hw_version = "{}.{}".format(slot_info.hardwareVersion.major,
                                slot_info.hardwareVersion.minor)
    slot_info_dict['hardwareVersion'] = hw_version
    fw_version = "{}.{}.{}".format(slot_info.firmwareVersion.major,
                                   slot_info.firmwareVersion.minor / 10,
                                   slot_info.firmwareVersion.minor % 10)
    slot_info_dict['firmwareVersion'] = fw_version
    return ret, slot_info_dict


def c_get_session_info(session):
    """Get information about the given session.

    :param int session: session handle
    :return: (retcode, dictionary of session information)
    :rtype: tuple
    """
    session_info = {}
    c_session_info = CK_SESSION_INFO()
    ret = C_GetSessionInfo(CK_SESSION_HANDLE(session), byref(c_session_info))

    if ret == CKR_OK:
        session_info['state'] = c_session_info.state
        session_info['flags'] = c_session_info.flags
        session_info['slotID'] = c_session_info.slotID
        session_info['usDeviceError'] = c_session_info.usDeviceError

    return ret, session_info


def c_get_token_info(slot_id, rstrip=True):
    """Gets the token info for a given slot id

    :param int slot_id: Token slot ID
    :param bool rstrip: If true, will strip trailing whitespace from char data.
    :returns: (retcode, A python dictionary representing the token info)
    :rtype: tuple
    """
    token_info = {}
    c_token_info = CK_TOKEN_INFO()
    LOG.info("Getting token info. slot=%s", slot_id)
    ret = C_GetTokenInfo(CK_ULONG(slot_id), byref(c_token_info))

    if ret == CKR_OK:
        token_info['label'] = string_at(c_token_info.label, 32)
        token_info['manufacturerID'] = string_at(c_token_info.manufacturerID, 32)
        token_info['model'] = string_at(c_token_info.model, 16)
        token_info['serialNumber'] = string_at(c_token_info.serialNumber, 16)
        token_info['flags'] = c_token_info.flags
        token_info['ulFreePrivateMemory'] = c_token_info.ulFreePrivateMemory
        token_info['ulTotalPrivateMemory'] = c_token_info.ulTotalPrivateMemory
        token_info['ulMaxSessionCount'] = c_token_info.usMaxSessionCount
        token_info['ulSessionCount'] = c_token_info.usSessionCount
        token_info['ulMaxRwSessionCount'] = c_token_info.usMaxRwSessionCount
        token_info['ulRwSessionCount'] = c_token_info.usRwSessionCount
        token_info['ulMaxPinLen'] = c_token_info.usMaxPinLen
        token_info['ulMinPinLen'] = c_token_info.usMinPinLen
        token_info['ulTotalPublicMemory'] = c_token_info.ulTotalPublicMemory
        token_info['ulFreePublicMemory'] = c_token_info.ulFreePublicMemory
        token_info['hardwareVersion'] = c_token_info.hardwareVersion
        token_info['firmwareVersion'] = c_token_info.firmwareVersion
        token_info['utcTime'] = string_at(c_token_info.utcTime, 16)
        if rstrip:
            token_info['label'] = token_info['label'].rstrip()
            token_info['manufacturerID'] = token_info['manufacturerID'].rstrip()
            token_info['model'] = token_info['model'].rstrip()
            token_info['serialNumber'] = token_info['serialNumber'].rstrip()
            token_info['utcTime'] = token_info['utcTime'].rstrip()

    return ret, token_info


def get_slot_dict(token_present=False):
    """Compiles a dictionary of the available slots


    :returns: A python dictionary of the available slots
    """
    ret, slot_list = c_get_slot_list(token_present)
    if (ret != 0): 
        return ret
    slot_dict = {}
    ret = CKR_OK
    for slot in slot_list:
        ret, data = c_get_slot_info(slot)
        if ret != CKR_OK:
            LOG.error("C_GetSlotInfo failed at slot %s")
            break
        slot_dict[slot] = data

    return ret, slot_dict


def c_close_session(h_session):
    """Closes a session

    :param int h_session: Session handle
    :returns: retcode
    :rtype: int
    """
    # CLOSE SESSION
    LOG.info("C_CloseSession: Closing session %s", h_session)
    ret = C_CloseSession(h_session)
    return ret


def c_logout(h_session):
    """Logs out of a given session

    :param int h_session: Session handle
    :returns: retcode
    :rtype: int
    """
    LOG.info("C_Logout: Logging out of session %s", h_session)
    ret = C_Logout(h_session)
    return ret


def c_init_pin(h_session, pin):
    """Initializes the PIN

    :param int h_session: Session handle
    :param pin: pin to c_initialize
    :returns: THe result code

    """

    LOG.info("C_InitPIN: Initializing PIN to %s", pin)
    pin = AutoCArray(data=pin)
    ret = C_InitPIN(h_session, pin.array, pin.size.contents)
    return ret


def c_set_pin(h_session, old_pass, new_pass):
    """Allows a user to change their PIN

    :param int h_session: Session handle
    :param old_pass: The user's old password
    :param new_pass: The user's desired new password
    :returns: The result code

    """
    LOG.info("C_SetPIN: Changing password. "
             "old_pass=%s, new_pass=%s", old_pass, new_pass)

    old_pass = AutoCArray(data=old_pass)
    new_pass = AutoCArray(data=new_pass)

    ret = C_SetPIN(h_session,
                   old_pass.array, old_pass.size.contents,
                   new_pass.array, new_pass.size.contents)
    return ret


def c_close_all_sessions(slot):
    """Closes all the sessions on a given slot

    :param slot: The slot to close all sessions on
    :returns: retcode
    :rtype: int
    """

    LOG.info("C_CloseAllSessions: Closing all sessions. slot=%s", slot)
    ret = C_CloseAllSessions(CK_ULONG(slot))
    return ret

def get_firmware_version(slot):
    """
    Calls to ``C_GetTokenInfo`` for the given slot.
    Returns a string representing the firmware version.

    :param int slot: Token slot number
    :return: Firmware String in the format "X.Y.Z", where X is major, Y is minor, Z is subminor.
    :rtype: str
    """

    ret, info = c_get_token_info(slot)
    raw_firmware = info['firmwareVersion']
    if ret != 0:
        return ret
    major = raw_firmware.major
    minor = raw_firmware.minor / 10
    subminor = raw_firmware.minor % 10

    return ret, "{}.{}.{}".format(major, minor, subminor)

