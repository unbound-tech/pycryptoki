#
# Please note that this file have been modified by Unbound Tech
#
"""
This file contains all of the ctypes definitions for the cryptoki library.
The ctypes definitions outline the structures for the cryptoki C API.
"""

import sys
from ctypes import *

from .cryptoki_helpers import make_late_binding_function


class CK_MECHANISM(Structure):
    pass


class CK_ATTRIBUTE(Structure):
    pass


CK_MECHANISM_PTR = POINTER(CK_MECHANISM)
CK_ATTRIBUTE_PTR = POINTER(CK_ATTRIBUTE)


# values for enumeration 'ResultCodeValue'
ResultCodeValue = c_int  # enum

# values for unnamed enumeration
CK_USHORT = c_ulong
CK_USHORT_PTR = POINTER(CK_USHORT)


class CK_AES_GCM_PARAMS(Structure):
    pass


CK_BYTE = c_ubyte
CK_BYTE_PTR = POINTER(CK_BYTE)
CK_ULONG = c_ulong
if 'win' in sys.platform:
    CK_AES_GCM_PARAMS._pack_ = 1
CK_AES_GCM_PARAMS._fields_ = [
    ('pIv', CK_BYTE_PTR),
    ('ulIvLen', CK_ULONG),
    ('ulIvBits', CK_ULONG),
    ('pAAD', CK_BYTE_PTR),
    ('ulAADLen', CK_ULONG),
    ('ulTagBits', CK_ULONG),
]
CK_AES_GCM_PARAMS_PTR = CK_AES_GCM_PARAMS


class CK_XOR_BASE_DATA_KDF_PARAMS(Structure):
    pass


CK_EC_KDF_TYPE = CK_ULONG
if 'win' in sys.platform:
    CK_XOR_BASE_DATA_KDF_PARAMS._pack_ = 1
CK_XOR_BASE_DATA_KDF_PARAMS._fields_ = [
    ('kdf', CK_EC_KDF_TYPE),
    ('ulSharedDataLen', CK_ULONG),
    ('pSharedData', CK_BYTE_PTR),
]
CK_XOR_BASE_DATA_KDF_PARAMS_PTR = POINTER(CK_XOR_BASE_DATA_KDF_PARAMS)


class CK_AES_XTS_PARAMS(Structure):
    pass


CK_OBJECT_HANDLE = CK_ULONG
if 'win' in sys.platform:
    CK_AES_XTS_PARAMS._pack_ = 1
CK_AES_XTS_PARAMS._fields_ = [
    ('hTweakKey', CK_OBJECT_HANDLE),
    ('cb', CK_BYTE * 16),
]
CK_AES_XTS_PARAMS_PTR = POINTER(CK_AES_XTS_PARAMS)
CK_EC_DH_PRIMITIVE = CK_ULONG
CK_EC_ENC_SCHEME = CK_ULONG
CK_EC_MAC_SCHEME = CK_ULONG


class CK_ECIES_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_ECIES_PARAMS._pack_ = 1
CK_ECIES_PARAMS._fields_ = [
    ('dhPrimitive', CK_EC_DH_PRIMITIVE),
    ('kdf', CK_EC_KDF_TYPE),
    ('ulSharedDataLen1', CK_ULONG),
    ('pSharedData1', CK_BYTE_PTR),
    ('encScheme', CK_EC_ENC_SCHEME),
    ('ulEncKeyLenInBits', CK_ULONG),
    ('macScheme', CK_EC_MAC_SCHEME),
    ('ulMacKeyLenInBits', CK_ULONG),
    ('ulMacLenInBits', CK_ULONG),
    ('ulSharedDataLen2', CK_ULONG),
    ('pSharedData2', CK_BYTE_PTR),
]
CK_ECIES_PARAMS_PTR = POINTER(CK_ECIES_PARAMS)
CK_KDF_PRF_TYPE = CK_ULONG
CK_KDF_PRF_ENCODING_SCHEME = CK_ULONG


class CK_KDF_PRF_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_KDF_PRF_PARAMS._pack_ = 1
CK_KDF_PRF_PARAMS._fields_ = [
    ('prfType', CK_KDF_PRF_TYPE),
    ('pLabel', CK_BYTE_PTR),
    ('ulLabelLen', CK_ULONG),
    ('pContext', CK_BYTE_PTR),
    ('ulContextLen', CK_ULONG),
    ('ulCounter', CK_ULONG),
    ('ulEncodingScheme', CK_KDF_PRF_ENCODING_SCHEME),
]
CK_PRF_KDF_PARAMS = CK_KDF_PRF_PARAMS
CK_KDF_PRF_PARAMS_PTR = POINTER(CK_PRF_KDF_PARAMS)


class CK_AES_CTR_PARAMS(Structure):
    pass


CK_SEED_CTR_PARAMS = CK_AES_CTR_PARAMS
CK_SEED_CTR_PARAMS_PTR = POINTER(CK_SEED_CTR_PARAMS)
CK_ARIA_CTR_PARAMS = CK_AES_CTR_PARAMS
CK_ARIA_CTR_PARAMS_PTR = POINTER(CK_ARIA_CTR_PARAMS)


class CK_DES_CTR_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_DES_CTR_PARAMS._pack_ = 1
CK_DES_CTR_PARAMS._fields_ = [
    ('ulCounterBits', CK_ULONG),
    ('cb', CK_BYTE * 8),
]
CK_DES_CTR_PARAMS_PTR = POINTER(CK_DES_CTR_PARAMS)
CK_AES_GMAC_PARAMS = CK_AES_GCM_PARAMS
CK_AES_GMAC_PARAMS_PTR = POINTER(CK_AES_GMAC_PARAMS)

CK_CHAR = CK_BYTE


class CK_VERSION(Structure):
    pass


if 'win' in sys.platform:
    CK_VERSION._pack_ = 1
CK_VERSION._fields_ = [
    ('major', CK_BYTE),
    ('minor', CK_BYTE),
]

class CK_HA_MEMBER(Structure):
    pass


CK_RV = CK_ULONG
if 'win' in sys.platform:
    CK_HA_MEMBER._pack_ = 1
CK_HA_MEMBER._fields_ = [
    ('memberSerial', CK_CHAR * 20),
    ('memberStatus', CK_RV),
]


class CK_HA_STATUS(Structure):
    pass


if 'win' in sys.platform:
    CK_HA_STATUS._pack_ = 1
CK_HA_STATUS._fields_ = [
    ('groupSerial', CK_CHAR * 20),
    ('memberList', CK_HA_MEMBER * 32),
    ('listSize', CK_ULONG),
]
CK_HA_MEMBER_PTR = POINTER(CK_HA_MEMBER)
CK_HA_STATE_PTR = POINTER(CK_HA_STATUS)
CKA_SIM_AUTH_FORM = CK_ULONG


class CT_Token(Structure):
    pass


if 'win' in sys.platform:
    CT_Token._pack_ = 1
CT_Token._fields_ = [
]
CT_TokenHndle = POINTER(CT_Token)


class CK_AES_CBC_PAD_EXTRACT_PARAMS(Structure):
    pass


CK_ULONG_PTR = POINTER(CK_ULONG)
if 'win' in sys.platform:
    CK_AES_CBC_PAD_EXTRACT_PARAMS._pack_ = 1
CK_AES_CBC_PAD_EXTRACT_PARAMS._fields_ = [
    ('ulType', CK_ULONG),
    ('ulHandle', CK_ULONG),
    ('ulDeleteAfterExtract', CK_ULONG),
    ('pBuffer', CK_BYTE_PTR),
    ('pulBufferLen', CK_ULONG_PTR),
    ('ulStorage', CK_ULONG),
    ('pedId', CK_ULONG),
    ('pbFileName', CK_BYTE_PTR),
    ('ctxID', CK_ULONG),
]
CK_AES_CBC_PAD_EXTRACT_PARAMS_PTR = POINTER(CK_AES_CBC_PAD_EXTRACT_PARAMS)


class CK_AES_CBC_PAD_INSERT_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_AES_CBC_PAD_INSERT_PARAMS._pack_ = 1
CK_AES_CBC_PAD_INSERT_PARAMS._fields_ = [
    ('ulStorageType', CK_ULONG),
    ('ulContainerState', CK_ULONG),
    ('pBuffer', CK_BYTE_PTR),
    ('ulBufferLen', CK_ULONG),
    ('pulType', CK_ULONG_PTR),
    ('pulHandle', CK_ULONG_PTR),
    ('ulStorage', CK_ULONG),
    ('pedId', CK_ULONG),
    ('pbFileName', CK_BYTE_PTR),
    ('ctxID', CK_ULONG),
]
CK_AES_CBC_PAD_INSERT_PARAMS_PTR = POINTER(CK_AES_CBC_PAD_INSERT_PARAMS)


class CK_CLUSTER_STATE(Structure):
    pass


if 'win' in sys.platform:
    CK_CLUSTER_STATE._pack_ = 1
CK_CLUSTER_STATE._fields_ = [
    ('bMembers', CK_BYTE * 32 * 8),
    ('ulMemberStatus', CK_ULONG * 8),
]
CK_CLUSTER_STATE_PTR = POINTER(CK_CLUSTER_STATE)


class CK_LKM_TOKEN_ID_S(Structure):
    pass


if 'win' in sys.platform:
    CK_LKM_TOKEN_ID_S._pack_ = 1
CK_LKM_TOKEN_ID_S._fields_ = [
    ('id', CK_BYTE * 20),
]
CK_LKM_TOKEN_ID = CK_LKM_TOKEN_ID_S
CK_LKM_TOKEN_ID_PTR = POINTER(CK_LKM_TOKEN_ID)


CK_FLAGS = CK_ULONG
CK_SLOT_ID = CK_ULONG
CK_SLOT_ID_PTR = POINTER(CK_SLOT_ID)
CK_VOID_PTR = c_void_p
CK_CHAR_PTR = POINTER(CK_CHAR)
CK_SESSION_HANDLE = CK_ULONG
CK_USER_TYPE = CK_ULONG
CK_NOTIFICATION = CK_ULONG
CK_NOTIFY = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR)
CK_SESSION_HANDLE_PTR = POINTER(CK_SESSION_HANDLE)
CK_OBJECT_HANDLE_PTR = POINTER(CK_OBJECT_HANDLE)
CK_BBOOL = CK_BYTE

CK_GetTotalOperations = CFUNCTYPE(CK_RV, CK_SLOT_ID, POINTER(c_int))
CK_ResetTotalOperations = CFUNCTYPE(CK_RV, CK_SLOT_ID)

# values for enumeration 'fwResultCode'
fwResultCode = c_int  # enum

# values for enumeration 'eInitMsgs'
eInitMsgs = c_int  # enum
SInt8 = c_byte
SInt16 = c_short
SInt32 = c_long
SInt = c_int
SInt64 = c_longlong
UInt8 = c_ubyte
UInt16 = c_ushort
UInt32 = c_ulong
UInt = c_uint
ULong = c_ulong
UInt64 = c_ulonglong
Int8 = c_char
Int16 = c_short
Int32 = c_long
Int = c_int
Int64 = c_longlong
Float32 = c_float
Float64 = c_double
Float = Float64
Byte = UInt8
BYTE = UInt8
HalfWord = UInt16
Word = UInt32
PointerDifference = SInt32
SizeType = UInt
Boolean = UInt8


class swapper(Union):
    pass


if 'win' in sys.platform:
    swapper._pack_ = 1
swapper._fields_ = [
    ('bytes', c_char * 4),
    ('words', c_int),
]
HANDLE = c_int


class CK_FUNCTION_LIST(Structure):
    pass


CK_C_Initialize = CFUNCTYPE(CK_RV, CK_VOID_PTR)
CK_C_Finalize = CFUNCTYPE(CK_RV, CK_VOID_PTR)


class CK_INFO(Structure):
    pass


CK_INFO_PTR = POINTER(CK_INFO)
CK_C_GetInfo = CFUNCTYPE(CK_RV, CK_INFO_PTR)
CK_FUNCTION_LIST_PTR = POINTER(CK_FUNCTION_LIST)
CK_FUNCTION_LIST_PTR_PTR = POINTER(CK_FUNCTION_LIST_PTR)
CK_C_GetFunctionList = CFUNCTYPE(CK_RV, CK_FUNCTION_LIST_PTR_PTR)
CK_C_GetSlotList = CFUNCTYPE(CK_RV, CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR)


class CK_SLOT_INFO(Structure):
    pass


CK_SLOT_INFO_PTR = POINTER(CK_SLOT_INFO)
CK_C_GetSlotInfo = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_SLOT_INFO_PTR)


class CK_TOKEN_INFO(Structure):
    pass


CK_TOKEN_INFO_PTR = POINTER(CK_TOKEN_INFO)
CK_C_GetTokenInfo = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_TOKEN_INFO_PTR)
CK_MECHANISM_TYPE = CK_ULONG
CK_MECHANISM_TYPE_PTR = POINTER(CK_MECHANISM_TYPE)
CK_C_GetMechanismList = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR)


class CK_MECHANISM_INFO(Structure):
    pass


CK_MECHANISM_INFO_PTR = POINTER(CK_MECHANISM_INFO)
CK_C_GetMechanismInfo = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR)
CK_UTF8CHAR = CK_BYTE
CK_UTF8CHAR_PTR = POINTER(CK_UTF8CHAR)
CK_C_InitToken = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR)
CK_C_InitPIN = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG)
CK_C_SetPIN = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR,
                        CK_ULONG)
CK_C_OpenSession = CFUNCTYPE(CK_RV, CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY,
                             CK_SESSION_HANDLE_PTR)
CK_C_CloseSession = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_C_CloseAllSessions = CFUNCTYPE(CK_RV, CK_SLOT_ID)


class CK_SESSION_INFO(Structure):
    pass


CK_SESSION_INFO_PTR = POINTER(CK_SESSION_INFO)
CK_C_GetSessionInfo = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_SESSION_INFO_PTR)
CK_C_GetOperationState = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_SetOperationState = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                                   CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)
CK_C_Login = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG)
CK_C_Logout = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_C_CreateObject = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG,
                              CK_OBJECT_HANDLE_PTR)
CK_C_CopyObject = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG,
                            CK_OBJECT_HANDLE_PTR)
CK_C_DestroyObject = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE)
CK_C_GetObjectSize = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR)
CK_C_GetAttributeValue = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR,
                                   CK_ULONG)
CK_C_SetAttributeValue = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR,
                                   CK_ULONG)
CK_C_FindObjectsInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG)
CK_C_FindObjects = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR)
CK_C_FindObjectsFinal = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_C_EncryptInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
CK_C_Encrypt = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_EncryptUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                               CK_ULONG_PTR)
CK_C_EncryptFinal = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_DecryptInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
CK_C_Decrypt = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_DecryptUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                               CK_ULONG_PTR)
CK_C_DecryptFinal = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_DigestInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR)
CK_C_Digest = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_DigestUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
CK_C_DigestKey = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE)
CK_C_DigestFinal = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_SignInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
CK_C_Sign = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_SignUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
CK_C_SignFinal = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_SignRecoverInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
CK_C_SignRecover = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                             CK_ULONG_PTR)
CK_C_VerifyInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
CK_C_Verify = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG)
CK_C_VerifyUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
CK_C_VerifyFinal = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
CK_C_VerifyRecoverInit = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE)
CK_C_VerifyRecover = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                               CK_ULONG_PTR)
CK_C_DigestEncryptUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                                     CK_ULONG_PTR)
CK_C_DecryptDigestUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                                     CK_ULONG_PTR)
CK_C_SignEncryptUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                                   CK_ULONG_PTR)
CK_C_DecryptVerifyUpdate = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                                     CK_ULONG_PTR)
CK_C_GenerateKey = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG,
                             CK_OBJECT_HANDLE_PTR)
CK_C_GenerateKeyPair = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR,
                                 CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR,
                                 CK_OBJECT_HANDLE_PTR)
CK_C_WrapKey = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
                         CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
CK_C_UnwrapKey = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
                           CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR)
CK_C_DeriveKey = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
                           CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR)
CK_C_SeedRandom = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
CK_C_GenerateRandom = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
CK_C_GetFunctionStatus = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_C_CancelFunction = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE)
CK_C_WaitForSlotEvent = CFUNCTYPE(CK_RV, CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR)

CK_DYC_SelfSignX509 = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_MECHANISM_TYPE, CK_CHAR_PTR,
                                CK_BYTE_PTR, CK_ULONG, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)
CK_DYC_SignX509 = CFUNCTYPE(CK_RV, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_MECHANISM_TYPE,
                            CK_BYTE_PTR, CK_ULONG,
                            CK_BYTE_PTR, CK_ULONG, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR)

if 'win' in sys.platform:
    CK_FUNCTION_LIST._pack_ = 1
CK_FUNCTION_LIST._fields_ = [
    ('version', CK_VERSION),
    ('C_Initialize', CK_C_Initialize),
    ('C_Finalize', CK_C_Finalize),
    ('C_GetInfo', CK_C_GetInfo),
    ('C_GetFunctionList', CK_C_GetFunctionList),
    ('C_GetSlotList', CK_C_GetSlotList),
    ('C_GetSlotInfo', CK_C_GetSlotInfo),
    ('C_GetTokenInfo', CK_C_GetTokenInfo),
    ('C_GetMechanismList', CK_C_GetMechanismList),
    ('C_GetMechanismInfo', CK_C_GetMechanismInfo),
    ('C_InitToken', CK_C_InitToken),
    ('C_InitPIN', CK_C_InitPIN),
    ('C_SetPIN', CK_C_SetPIN),
    ('C_OpenSession', CK_C_OpenSession),
    ('C_CloseSession', CK_C_CloseSession),
    ('C_CloseAllSessions', CK_C_CloseAllSessions),
    ('C_GetSessionInfo', CK_C_GetSessionInfo),
    ('C_GetOperationState', CK_C_GetOperationState),
    ('C_SetOperationState', CK_C_SetOperationState),
    ('C_Login', CK_C_Login),
    ('C_Logout', CK_C_Logout),
    ('C_CreateObject', CK_C_CreateObject),
    ('C_CopyObject', CK_C_CopyObject),
    ('C_DestroyObject', CK_C_DestroyObject),
    ('C_GetObjectSize', CK_C_GetObjectSize),
    ('C_GetAttributeValue', CK_C_GetAttributeValue),
    ('C_SetAttributeValue', CK_C_SetAttributeValue),
    ('C_FindObjectsInit', CK_C_FindObjectsInit),
    ('C_FindObjects', CK_C_FindObjects),
    ('C_FindObjectsFinal', CK_C_FindObjectsFinal),
    ('C_EncryptInit', CK_C_EncryptInit),
    ('C_Encrypt', CK_C_Encrypt),
    ('C_EncryptUpdate', CK_C_EncryptUpdate),
    ('C_EncryptFinal', CK_C_EncryptFinal),
    ('C_DecryptInit', CK_C_DecryptInit),
    ('C_Decrypt', CK_C_Decrypt),
    ('C_DecryptUpdate', CK_C_DecryptUpdate),
    ('C_DecryptFinal', CK_C_DecryptFinal),
    ('C_DigestInit', CK_C_DigestInit),
    ('C_Digest', CK_C_Digest),
    ('C_DigestUpdate', CK_C_DigestUpdate),
    ('C_DigestKey', CK_C_DigestKey),
    ('C_DigestFinal', CK_C_DigestFinal),
    ('C_SignInit', CK_C_SignInit),
    ('C_Sign', CK_C_Sign),
    ('C_SignUpdate', CK_C_SignUpdate),
    ('C_SignFinal', CK_C_SignFinal),
    ('C_SignRecoverInit', CK_C_SignRecoverInit),
    ('C_SignRecover', CK_C_SignRecover),
    ('C_VerifyInit', CK_C_VerifyInit),
    ('C_Verify', CK_C_Verify),
    ('C_VerifyUpdate', CK_C_VerifyUpdate),
    ('C_VerifyFinal', CK_C_VerifyFinal),
    ('C_VerifyRecoverInit', CK_C_VerifyRecoverInit),
    ('C_VerifyRecover', CK_C_VerifyRecover),
    ('C_DigestEncryptUpdate', CK_C_DigestEncryptUpdate),
    ('C_DecryptDigestUpdate', CK_C_DecryptDigestUpdate),
    ('C_SignEncryptUpdate', CK_C_SignEncryptUpdate),
    ('C_DecryptVerifyUpdate', CK_C_DecryptVerifyUpdate),
    ('C_GenerateKey', CK_C_GenerateKey),
    ('C_GenerateKeyPair', CK_C_GenerateKeyPair),
    ('C_WrapKey', CK_C_WrapKey),
    ('C_UnwrapKey', CK_C_UnwrapKey),
    ('C_DeriveKey', CK_C_DeriveKey),
    ('C_SeedRandom', CK_C_SeedRandom),
    ('C_GenerateRandom', CK_C_GenerateRandom),
    ('C_GetFunctionStatus', CK_C_GetFunctionStatus),
    ('C_CancelFunction', CK_C_CancelFunction),
    ('C_WaitForSlotEvent', CK_C_WaitForSlotEvent),
    ('DYC_SelfSignX509', CK_DYC_SelfSignX509),
    ('DYC_SignX509', CK_DYC_SignX509),
]

C_Initialize = make_late_binding_function('C_Initialize')
C_Initialize.restype = CK_RV
C_Initialize.argtypes = [CK_VOID_PTR]
C_Finalize = make_late_binding_function('C_Finalize')
C_Finalize.restype = CK_RV
C_Finalize.argtypes = [CK_VOID_PTR]
C_GetInfo = make_late_binding_function('C_GetInfo')
C_GetInfo.restype = CK_RV
C_GetInfo.argtypes = [CK_INFO_PTR]
C_GetFunctionList = make_late_binding_function('C_GetFunctionList')
C_GetFunctionList.restype = CK_RV
C_GetFunctionList.argtypes = [CK_FUNCTION_LIST_PTR_PTR]
C_GetSlotList = make_late_binding_function('C_GetSlotList')
C_GetSlotList.restype = CK_RV
C_GetSlotList.argtypes = [CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR]
C_GetSlotInfo = make_late_binding_function('C_GetSlotInfo')
C_GetSlotInfo.restype = CK_RV
C_GetSlotInfo.argtypes = [CK_SLOT_ID, CK_SLOT_INFO_PTR]
C_GetTokenInfo = make_late_binding_function('C_GetTokenInfo')
C_GetTokenInfo.restype = CK_RV
C_GetTokenInfo.argtypes = [CK_SLOT_ID, CK_TOKEN_INFO_PTR]
C_GetMechanismList = make_late_binding_function('C_GetMechanismList')
C_GetMechanismList.restype = CK_RV
C_GetMechanismList.argtypes = [CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR]
C_GetMechanismInfo = make_late_binding_function('C_GetMechanismInfo')
C_GetMechanismInfo.restype = CK_RV
C_GetMechanismInfo.argtypes = [CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR]
C_InitToken = make_late_binding_function('C_InitToken')
C_InitToken.restype = CK_RV
C_InitToken.argtypes = [CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR]
C_InitPIN = make_late_binding_function('C_InitPIN')
C_InitPIN.restype = CK_RV
C_InitPIN.argtypes = [CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG]
C_SetPIN = make_late_binding_function('C_SetPIN')
C_SetPIN.restype = CK_RV
C_SetPIN.argtypes = [CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG]
C_OpenSession = make_late_binding_function('C_OpenSession')
C_OpenSession.restype = CK_RV
C_OpenSession.argtypes = [CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR]
C_CloseSession = make_late_binding_function('C_CloseSession')
C_CloseSession.restype = CK_RV
C_CloseSession.argtypes = [CK_SESSION_HANDLE]
C_CloseAllSessions = make_late_binding_function('C_CloseAllSessions')
C_CloseAllSessions.restype = CK_RV
C_CloseAllSessions.argtypes = [CK_SLOT_ID]
C_GetSessionInfo = make_late_binding_function('C_GetSessionInfo')
C_GetSessionInfo.restype = CK_RV
C_GetSessionInfo.argtypes = [CK_SESSION_HANDLE, CK_SESSION_INFO_PTR]
C_GetOperationState = make_late_binding_function('C_GetOperationState')
C_GetOperationState.restype = CK_RV
C_GetOperationState.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_SetOperationState = make_late_binding_function('C_SetOperationState')
C_SetOperationState.restype = CK_RV
C_SetOperationState.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE,
                                CK_OBJECT_HANDLE]
C_Login = make_late_binding_function('C_Login')
C_Login.restype = CK_RV
C_Login.argtypes = [CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG]
C_Logout = make_late_binding_function('C_Logout')
C_Logout.restype = CK_RV
C_Logout.argtypes = [CK_SESSION_HANDLE]
C_CreateObject = make_late_binding_function('C_CreateObject')
C_CreateObject.restype = CK_RV
C_CreateObject.argtypes = [CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR]
C_CopyObject = make_late_binding_function('C_CopyObject')
C_CopyObject.restype = CK_RV
C_CopyObject.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG,
                         CK_OBJECT_HANDLE_PTR]
C_DestroyObject = make_late_binding_function('C_DestroyObject')
C_DestroyObject.restype = CK_RV
C_DestroyObject.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
C_GetObjectSize = make_late_binding_function('C_GetObjectSize')
C_GetObjectSize.restype = CK_RV
C_GetObjectSize.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR]
C_GetAttributeValue = make_late_binding_function('C_GetAttributeValue')
C_GetAttributeValue.restype = CK_RV
C_GetAttributeValue.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG]
C_SetAttributeValue = make_late_binding_function('C_SetAttributeValue')
C_SetAttributeValue.restype = CK_RV
C_SetAttributeValue.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG]
C_FindObjectsInit = make_late_binding_function('C_FindObjectsInit')
C_FindObjectsInit.restype = CK_RV
C_FindObjectsInit.argtypes = [CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG]
C_FindObjects = make_late_binding_function('C_FindObjects')
C_FindObjects.restype = CK_RV
C_FindObjects.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR]
C_FindObjectsFinal = make_late_binding_function('C_FindObjectsFinal')
C_FindObjectsFinal.restype = CK_RV
C_FindObjectsFinal.argtypes = [CK_SESSION_HANDLE]
C_EncryptInit = make_late_binding_function('C_EncryptInit')
C_EncryptInit.restype = CK_RV
C_EncryptInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_Encrypt = make_late_binding_function('C_Encrypt')
C_Encrypt.restype = CK_RV
C_Encrypt.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_EncryptUpdate = make_late_binding_function('C_EncryptUpdate')
C_EncryptUpdate.restype = CK_RV
C_EncryptUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_EncryptFinal = make_late_binding_function('C_EncryptFinal')
C_EncryptFinal.restype = CK_RV
C_EncryptFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_DecryptInit = make_late_binding_function('C_DecryptInit')
C_DecryptInit.restype = CK_RV
C_DecryptInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_Decrypt = make_late_binding_function('C_Decrypt')
C_Decrypt.restype = CK_RV
C_Decrypt.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DecryptUpdate = make_late_binding_function('C_DecryptUpdate')
C_DecryptUpdate.restype = CK_RV
C_DecryptUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DecryptFinal = make_late_binding_function('C_DecryptFinal')
C_DecryptFinal.restype = CK_RV
C_DecryptFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_DigestInit = make_late_binding_function('C_DigestInit')
C_DigestInit.restype = CK_RV
C_DigestInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR]
C_Digest = make_late_binding_function('C_Digest')
C_Digest.restype = CK_RV
C_Digest.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DigestUpdate = make_late_binding_function('C_DigestUpdate')
C_DigestUpdate.restype = CK_RV
C_DigestUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_DigestKey = make_late_binding_function('C_DigestKey')
C_DigestKey.restype = CK_RV
C_DigestKey.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
C_DigestFinal = make_late_binding_function('C_DigestFinal')
C_DigestFinal.restype = CK_RV
C_DigestFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_SignInit = make_late_binding_function('C_SignInit')
C_SignInit.restype = CK_RV
C_SignInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_Sign = make_late_binding_function('C_Sign')
C_Sign.restype = CK_RV
C_Sign.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_SignUpdate = make_late_binding_function('C_SignUpdate')
C_SignUpdate.restype = CK_RV
C_SignUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_SignFinal = make_late_binding_function('C_SignFinal')
C_SignFinal.restype = CK_RV
C_SignFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR]
C_SignRecoverInit = make_late_binding_function('C_SignRecoverInit')
C_SignRecoverInit.restype = CK_RV
C_SignRecoverInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_SignRecover = make_late_binding_function('C_SignRecover')
C_SignRecover.restype = CK_RV
C_SignRecover.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_VerifyInit = make_late_binding_function('C_VerifyInit')
C_VerifyInit.restype = CK_RV
C_VerifyInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_Verify = make_late_binding_function('C_Verify')
C_Verify.restype = CK_RV
C_Verify.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG]
C_VerifyUpdate = make_late_binding_function('C_VerifyUpdate')
C_VerifyUpdate.restype = CK_RV
C_VerifyUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_VerifyFinal = make_late_binding_function('C_VerifyFinal')
C_VerifyFinal.restype = CK_RV
C_VerifyFinal.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_VerifyRecoverInit = make_late_binding_function('C_VerifyRecoverInit')
C_VerifyRecoverInit.restype = CK_RV
C_VerifyRecoverInit.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE]
C_VerifyRecover = make_late_binding_function('C_VerifyRecover')
C_VerifyRecover.restype = CK_RV
C_VerifyRecover.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DigestEncryptUpdate = make_late_binding_function('C_DigestEncryptUpdate')
C_DigestEncryptUpdate.restype = CK_RV
C_DigestEncryptUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                                  CK_ULONG_PTR]
C_DecryptDigestUpdate = make_late_binding_function('C_DecryptDigestUpdate')
C_DecryptDigestUpdate.restype = CK_RV
C_DecryptDigestUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                                  CK_ULONG_PTR]
C_SignEncryptUpdate = make_late_binding_function('C_SignEncryptUpdate')
C_SignEncryptUpdate.restype = CK_RV
C_SignEncryptUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]
C_DecryptVerifyUpdate = make_late_binding_function('C_DecryptVerifyUpdate')
C_DecryptVerifyUpdate.restype = CK_RV
C_DecryptVerifyUpdate.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                                  CK_ULONG_PTR]
C_GenerateKey = make_late_binding_function('C_GenerateKey')
C_GenerateKey.restype = CK_RV
C_GenerateKey.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG,
                          CK_OBJECT_HANDLE_PTR]
C_GenerateKeyPair = make_late_binding_function('C_GenerateKeyPair')
C_GenerateKeyPair.restype = CK_RV
C_GenerateKeyPair.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG,
                              CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR,
                              CK_OBJECT_HANDLE_PTR]
C_WrapKey = make_late_binding_function('C_WrapKey')
C_WrapKey.restype = CK_RV
C_WrapKey.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE,
                      CK_BYTE_PTR, CK_ULONG_PTR]
C_UnwrapKey = make_late_binding_function('C_UnwrapKey')
C_UnwrapKey.restype = CK_RV
C_UnwrapKey.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_BYTE_PTR,
                        CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR]
C_DeriveKey = make_late_binding_function('C_DeriveKey')
C_DeriveKey.restype = CK_RV
C_DeriveKey.argtypes = [CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR,
                        CK_ULONG, CK_OBJECT_HANDLE_PTR]
C_SeedRandom = make_late_binding_function('C_SeedRandom')
C_SeedRandom.restype = CK_RV
C_SeedRandom.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_GenerateRandom = make_late_binding_function('C_GenerateRandom')
C_GenerateRandom.restype = CK_RV
C_GenerateRandom.argtypes = [CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG]
C_GetFunctionStatus = make_late_binding_function('C_GetFunctionStatus')
C_GetFunctionStatus.restype = CK_RV
C_GetFunctionStatus.argtypes = [CK_SESSION_HANDLE]
C_CancelFunction = make_late_binding_function('C_CancelFunction')
C_CancelFunction.restype = CK_RV
C_CancelFunction.argtypes = [CK_SESSION_HANDLE]
C_WaitForSlotEvent = make_late_binding_function('C_WaitForSlotEvent')
C_WaitForSlotEvent.restype = CK_RV
C_WaitForSlotEvent.argtypes = [CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR]

DYC_SelfSignX509 = make_late_binding_function('DYC_SelfSignX509')
DYC_SelfSignX509.restype = CK_RV
DYC_SelfSignX509.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_MECHANISM_TYPE, CK_CHAR_PTR,
                             CK_BYTE_PTR, CK_ULONG, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]

DYC_SignX509 = make_late_binding_function('DYC_SignX509')
DYC_SignX509.restype = CK_RV
DYC_SignX509.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_MECHANISM_TYPE,
                         CK_BYTE_PTR, CK_ULONG,
                         CK_BYTE_PTR, CK_ULONG, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR]


CK_LONG = c_long
CK_VOID_PTR_PTR = POINTER(CK_VOID_PTR)
CK_VERSION_PTR = POINTER(CK_VERSION)
if 'win' in sys.platform:
    CK_INFO._pack_ = 1
CK_INFO._fields_ = [
    ('cryptokiVersion', CK_VERSION),
    ('manufacturerID', CK_UTF8CHAR * 32),
    ('flags', CK_FLAGS),
    ('libraryDescription', CK_UTF8CHAR * 32),
    ('libraryVersion', CK_VERSION),
]
if 'win' in sys.platform:
    CK_SLOT_INFO._pack_ = 1
CK_SLOT_INFO._fields_ = [
    ('slotDescription', CK_UTF8CHAR * 64),
    ('manufacturerID', CK_UTF8CHAR * 32),
    ('flags', CK_FLAGS),
    ('hardwareVersion', CK_VERSION),
    ('firmwareVersion', CK_VERSION),
]
if 'win' in sys.platform:
    CK_TOKEN_INFO._pack_ = 1
CK_TOKEN_INFO._fields_ = [
    ('label', CK_UTF8CHAR * 32),
    ('manufacturerID', CK_UTF8CHAR * 32),
    ('model', CK_UTF8CHAR * 16),
    ('serialNumber', CK_CHAR * 16),
    ('flags', CK_FLAGS),
    ('usMaxSessionCount', CK_ULONG),
    ('usSessionCount', CK_ULONG),
    ('usMaxRwSessionCount', CK_ULONG),
    ('usRwSessionCount', CK_ULONG),
    ('usMaxPinLen', CK_ULONG),
    ('usMinPinLen', CK_ULONG),
    ('ulTotalPublicMemory', CK_ULONG),
    ('ulFreePublicMemory', CK_ULONG),
    ('ulTotalPrivateMemory', CK_ULONG),
    ('ulFreePrivateMemory', CK_ULONG),
    ('hardwareVersion', CK_VERSION),
    ('firmwareVersion', CK_VERSION),
    ('utcTime', CK_CHAR * 16),
]
CK_STATE = CK_ULONG
if 'win' in sys.platform:
    CK_SESSION_INFO._pack_ = 1
CK_SESSION_INFO._fields_ = [
    ('slotID', CK_SLOT_ID),
    ('state', CK_STATE),
    ('flags', CK_FLAGS),
    ('usDeviceError', CK_ULONG),
]
CK_OBJECT_CLASS = CK_ULONG
CK_OBJECT_CLASS_PTR = POINTER(CK_OBJECT_CLASS)
CK_HW_FEATURE_TYPE = CK_ULONG
CK_KEY_TYPE = CK_ULONG
CK_CERTIFICATE_TYPE = CK_ULONG
CK_ATTRIBUTE_TYPE = CK_ULONG
if 'win' in sys.platform:
    CK_ATTRIBUTE._pack_ = 1
CK_ATTRIBUTE._fields_ = [
    ('type', CK_ATTRIBUTE_TYPE),
    ('pValue', CK_VOID_PTR),
    ('usValueLen', CK_ULONG),
]


class CK_DATE(Structure):
    pass


if 'win' in sys.platform:
    CK_DATE._pack_ = 1
CK_DATE._fields_ = [
    ('year', CK_CHAR * 4),
    ('month', CK_CHAR * 2),
    ('day', CK_CHAR * 2),
]
if 'win' in sys.platform:
    CK_MECHANISM._pack_ = 1
CK_MECHANISM._fields_ = [
    ('mechanism', CK_MECHANISM_TYPE),
    ('pParameter', CK_VOID_PTR),
    ('usParameterLen', CK_ULONG),
]
if 'win' in sys.platform:
    CK_MECHANISM_INFO._pack_ = 1
CK_MECHANISM_INFO._fields_ = [
    ('ulMinKeySize', CK_ULONG),
    ('ulMaxKeySize', CK_ULONG),
    ('flags', CK_FLAGS),
]
CK_CREATEMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR_PTR)
CK_DESTROYMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR)
CK_LOCKMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR)
CK_UNLOCKMUTEX = CFUNCTYPE(CK_RV, CK_VOID_PTR)


class CK_C_INITIALIZE_ARGS(Structure):
    pass


if 'win' in sys.platform:
    CK_C_INITIALIZE_ARGS._pack_ = 1
CK_C_INITIALIZE_ARGS._fields_ = [
    ('CreateMutex', CK_CREATEMUTEX),
    ('DestroyMutex', CK_DESTROYMUTEX),
    ('LockMutex', CK_LOCKMUTEX),
    ('UnlockMutex', CK_UNLOCKMUTEX),
    ('flags', CK_FLAGS),
    ('pReserved', CK_VOID_PTR),
]
CK_C_INITIALIZE_ARGS_PTR = POINTER(CK_C_INITIALIZE_ARGS)
CK_RSA_PKCS_MGF_TYPE = CK_ULONG
CK_RSA_PKCS_MGF_TYPE_PTR = POINTER(CK_RSA_PKCS_MGF_TYPE)
CK_RSA_PKCS_OAEP_SOURCE_TYPE = CK_ULONG
CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR = POINTER(CK_RSA_PKCS_OAEP_SOURCE_TYPE)


class CK_RSA_PKCS_OAEP_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_RSA_PKCS_OAEP_PARAMS._pack_ = 1
CK_RSA_PKCS_OAEP_PARAMS._fields_ = [
    ('hashAlg', CK_MECHANISM_TYPE),
    ('mgf', CK_RSA_PKCS_MGF_TYPE),
    ('source', CK_RSA_PKCS_OAEP_SOURCE_TYPE),
    ('pSourceData', CK_VOID_PTR),
    ('ulSourceDataLen', CK_ULONG),
]
CK_RSA_PKCS_OAEP_PARAMS_PTR = POINTER(CK_RSA_PKCS_OAEP_PARAMS)


class CK_RSA_PKCS_PSS_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_RSA_PKCS_PSS_PARAMS._pack_ = 1
CK_RSA_PKCS_PSS_PARAMS._fields_ = [
    ('hashAlg', CK_MECHANISM_TYPE),
    ('mgf', CK_RSA_PKCS_MGF_TYPE),
    ('usSaltLen', CK_ULONG),
]
CK_RSA_PKCS_PSS_PARAMS_PTR = POINTER(CK_RSA_PKCS_PSS_PARAMS)


class CK_ECDH1_DERIVE_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_ECDH1_DERIVE_PARAMS._pack_ = 1
CK_ECDH1_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_EC_KDF_TYPE),
    ('ulSharedDataLen', CK_ULONG),
    ('pSharedData', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
]
CK_ECDH1_DERIVE_PARAMS_PTR = POINTER(CK_ECDH1_DERIVE_PARAMS)


class CK_ECDH2_DERIVE_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_ECDH2_DERIVE_PARAMS._pack_ = 1
CK_ECDH2_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_EC_KDF_TYPE),
    ('ulSharedDataLen', CK_ULONG),
    ('pSharedData', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
    ('ulPrivateDataLen', CK_ULONG),
    ('hPrivateData', CK_OBJECT_HANDLE),
    ('ulPublicDataLen2', CK_ULONG),
    ('pPublicData2', CK_BYTE_PTR),
]
CK_ECDH2_DERIVE_PARAMS_PTR = POINTER(CK_ECDH2_DERIVE_PARAMS)


class CK_ECMQV_DERIVE_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_ECMQV_DERIVE_PARAMS._pack_ = 1
CK_ECMQV_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_EC_KDF_TYPE),
    ('ulSharedDataLen', CK_ULONG),
    ('pSharedData', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
    ('ulPrivateDataLen', CK_ULONG),
    ('hPrivateData', CK_OBJECT_HANDLE),
    ('ulPublicDataLen2', CK_ULONG),
    ('pPublicData2', CK_BYTE_PTR),
    ('publicKey', CK_OBJECT_HANDLE),
]
CK_ECMQV_DERIVE_PARAMS_PTR = POINTER(CK_ECMQV_DERIVE_PARAMS)
CK_X9_42_DH_KDF_TYPE = CK_ULONG
CK_X9_42_DH_KDF_TYPE_PTR = POINTER(CK_X9_42_DH_KDF_TYPE)


class CK_X9_42_DH1_DERIVE_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_X9_42_DH1_DERIVE_PARAMS._pack_ = 1
CK_X9_42_DH1_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_X9_42_DH_KDF_TYPE),
    ('ulOtherInfoLen', CK_ULONG),
    ('pOtherInfo', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
]
CK_X9_42_DH1_DERIVE_PARAMS_PTR = POINTER(CK_X9_42_DH1_DERIVE_PARAMS)


class CK_X9_42_DH2_DERIVE_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_X9_42_DH2_DERIVE_PARAMS._pack_ = 1
CK_X9_42_DH2_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_X9_42_DH_KDF_TYPE),
    ('ulOtherInfoLen', CK_ULONG),
    ('pOtherInfo', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
    ('ulPrivateDataLen', CK_ULONG),
    ('hPrivateData', CK_OBJECT_HANDLE),
    ('ulPublicDataLen2', CK_ULONG),
    ('pPublicData2', CK_BYTE_PTR),
]
CK_X9_42_DH2_DERIVE_PARAMS_PTR = POINTER(CK_X9_42_DH2_DERIVE_PARAMS)


class CK_X9_42_MQV_DERIVE_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_X9_42_MQV_DERIVE_PARAMS._pack_ = 1
CK_X9_42_MQV_DERIVE_PARAMS._fields_ = [
    ('kdf', CK_X9_42_DH_KDF_TYPE),
    ('ulOtherInfoLen', CK_ULONG),
    ('pOtherInfo', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
    ('ulPrivateDataLen', CK_ULONG),
    ('hPrivateData', CK_OBJECT_HANDLE),
    ('ulPublicDataLen2', CK_ULONG),
    ('pPublicData2', CK_BYTE_PTR),
    ('publicKey', CK_OBJECT_HANDLE),
]
CK_X9_42_MQV_DERIVE_PARAMS_PTR = POINTER(CK_X9_42_MQV_DERIVE_PARAMS)


class CK_KEA_DERIVE_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_KEA_DERIVE_PARAMS._pack_ = 1
CK_KEA_DERIVE_PARAMS._fields_ = [
    ('isSender', CK_BBOOL),
    ('ulRandomLen', CK_ULONG),
    ('pRandomA', CK_BYTE_PTR),
    ('pRandomB', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
]
CK_KEA_DERIVE_PARAMS_PTR = POINTER(CK_KEA_DERIVE_PARAMS)
CK_RC2_PARAMS = CK_ULONG
CK_RC2_PARAMS_PTR = POINTER(CK_RC2_PARAMS)


class CK_RC2_CBC_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_RC2_CBC_PARAMS._pack_ = 1
CK_RC2_CBC_PARAMS._fields_ = [
    ('usEffectiveBits', CK_ULONG),
    ('iv', CK_BYTE * 8),
]
CK_RC2_CBC_PARAMS_PTR = POINTER(CK_RC2_CBC_PARAMS)


class CK_RC2_MAC_GENERAL_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_RC2_MAC_GENERAL_PARAMS._pack_ = 1
CK_RC2_MAC_GENERAL_PARAMS._fields_ = [
    ('usEffectiveBits', CK_ULONG),
    ('ulMacLength', CK_ULONG),
]
CK_RC2_MAC_GENERAL_PARAMS_PTR = POINTER(CK_RC2_MAC_GENERAL_PARAMS)


class CK_RC5_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_RC5_PARAMS._pack_ = 1
CK_RC5_PARAMS._fields_ = [
    ('ulWordsize', CK_ULONG),
    ('ulRounds', CK_ULONG),
]
CK_RC5_PARAMS_PTR = POINTER(CK_RC5_PARAMS)


class CK_RC5_CBC_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_RC5_CBC_PARAMS._pack_ = 1
CK_RC5_CBC_PARAMS._fields_ = [
    ('ulWordsize', CK_ULONG),
    ('ulRounds', CK_ULONG),
    ('pIv', CK_BYTE_PTR),
    ('ulIvLen', CK_ULONG),
]
CK_RC5_CBC_PARAMS_PTR = POINTER(CK_RC5_CBC_PARAMS)


class CK_RC5_MAC_GENERAL_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_RC5_MAC_GENERAL_PARAMS._pack_ = 1
CK_RC5_MAC_GENERAL_PARAMS._fields_ = [
    ('ulWordsize', CK_ULONG),
    ('ulRounds', CK_ULONG),
    ('ulMacLength', CK_ULONG),
]
CK_RC5_MAC_GENERAL_PARAMS_PTR = POINTER(CK_RC5_MAC_GENERAL_PARAMS)
CK_MAC_GENERAL_PARAMS = CK_ULONG
CK_MAC_GENERAL_PARAMS_PTR = POINTER(CK_MAC_GENERAL_PARAMS)


class CK_DES_CBC_ENCRYPT_DATA_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_DES_CBC_ENCRYPT_DATA_PARAMS._pack_ = 1
CK_DES_CBC_ENCRYPT_DATA_PARAMS._fields_ = [
    ('iv', CK_BYTE * 8),
    ('pData', CK_BYTE_PTR),
    ('length', CK_ULONG),
]
CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR = POINTER(CK_DES_CBC_ENCRYPT_DATA_PARAMS)


class CK_AES_CBC_ENCRYPT_DATA_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_AES_CBC_ENCRYPT_DATA_PARAMS._pack_ = 1
CK_AES_CBC_ENCRYPT_DATA_PARAMS._fields_ = [
    ('iv', CK_BYTE * 16),
    ('pData', CK_BYTE_PTR),
    ('length', CK_ULONG),
]
CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR = POINTER(CK_AES_CBC_ENCRYPT_DATA_PARAMS)


class CK_SKIPJACK_PRIVATE_WRAP_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_SKIPJACK_PRIVATE_WRAP_PARAMS._pack_ = 1
CK_SKIPJACK_PRIVATE_WRAP_PARAMS._fields_ = [
    ('usPasswordLen', CK_ULONG),
    ('pPassword', CK_BYTE_PTR),
    ('ulPublicDataLen', CK_ULONG),
    ('pPublicData', CK_BYTE_PTR),
    ('ulPAndGLen', CK_ULONG),
    ('ulQLen', CK_ULONG),
    ('ulRandomLen', CK_ULONG),
    ('pRandomA', CK_BYTE_PTR),
    ('pPrimeP', CK_BYTE_PTR),
    ('pBaseG', CK_BYTE_PTR),
    ('pSubprimeQ', CK_BYTE_PTR),
]
CK_SKIPJACK_PRIVATE_WRAP_PTR = POINTER(CK_SKIPJACK_PRIVATE_WRAP_PARAMS)


class CK_SKIPJACK_RELAYX_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_SKIPJACK_RELAYX_PARAMS._pack_ = 1
CK_SKIPJACK_RELAYX_PARAMS._fields_ = [
    ('ulOldWrappedXLen', CK_ULONG),
    ('pOldWrappedX', CK_BYTE_PTR),
    ('ulOldPasswordLen', CK_ULONG),
    ('pOldPassword', CK_BYTE_PTR),
    ('ulOldPublicDataLen', CK_ULONG),
    ('pOldPublicData', CK_BYTE_PTR),
    ('ulOldRandomLen', CK_ULONG),
    ('pOldRandomA', CK_BYTE_PTR),
    ('ulNewPasswordLen', CK_ULONG),
    ('pNewPassword', CK_BYTE_PTR),
    ('ulNewPublicDataLen', CK_ULONG),
    ('pNewPublicData', CK_BYTE_PTR),
    ('ulNewRandomLen', CK_ULONG),
    ('pNewRandomA', CK_BYTE_PTR),
]
CK_SKIPJACK_RELAYX_PARAMS_PTR = POINTER(CK_SKIPJACK_RELAYX_PARAMS)


class CK_PBE_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_PBE_PARAMS._pack_ = 1
CK_PBE_PARAMS._fields_ = [
    ('pInitVector', CK_BYTE_PTR),
    ('pPassword', CK_UTF8CHAR_PTR),
    ('usPasswordLen', CK_ULONG),
    ('pSalt', CK_BYTE_PTR),
    ('usSaltLen', CK_ULONG),
    ('usIteration', CK_ULONG),
]
CK_PBE_PARAMS_PTR = POINTER(CK_PBE_PARAMS)


class CK_KEY_WRAP_SET_OAEP_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_KEY_WRAP_SET_OAEP_PARAMS._pack_ = 1
CK_KEY_WRAP_SET_OAEP_PARAMS._fields_ = [
    ('bBC', CK_BYTE),
    ('pX', CK_BYTE_PTR),
    ('ulXLen', CK_ULONG),
]
CK_KEY_WRAP_SET_OAEP_PARAMS_PTR = POINTER(CK_KEY_WRAP_SET_OAEP_PARAMS)


class CK_SSL3_RANDOM_DATA(Structure):
    pass


if 'win' in sys.platform:
    CK_SSL3_RANDOM_DATA._pack_ = 1
CK_SSL3_RANDOM_DATA._fields_ = [
    ('pClientRandom', CK_BYTE_PTR),
    ('ulClientRandomLen', CK_ULONG),
    ('pServerRandom', CK_BYTE_PTR),
    ('ulServerRandomLen', CK_ULONG),
]


class CK_SSL3_MASTER_KEY_DERIVE_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_SSL3_MASTER_KEY_DERIVE_PARAMS._pack_ = 1
CK_SSL3_MASTER_KEY_DERIVE_PARAMS._fields_ = [
    ('RandomInfo', CK_SSL3_RANDOM_DATA),
    ('pVersion', CK_VERSION_PTR),
]
CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR = POINTER(CK_SSL3_MASTER_KEY_DERIVE_PARAMS)


class CK_SSL3_KEY_MAT_OUT(Structure):
    pass


if 'win' in sys.platform:
    CK_SSL3_KEY_MAT_OUT._pack_ = 1
CK_SSL3_KEY_MAT_OUT._fields_ = [
    ('hClientMacSecret', CK_OBJECT_HANDLE),
    ('hServerMacSecret', CK_OBJECT_HANDLE),
    ('hClientKey', CK_OBJECT_HANDLE),
    ('hServerKey', CK_OBJECT_HANDLE),
    ('pIVClient', CK_BYTE_PTR),
    ('pIVServer', CK_BYTE_PTR),
]
CK_SSL3_KEY_MAT_OUT_PTR = POINTER(CK_SSL3_KEY_MAT_OUT)


class CK_SSL3_KEY_MAT_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_SSL3_KEY_MAT_PARAMS._pack_ = 1
CK_SSL3_KEY_MAT_PARAMS._fields_ = [
    ('ulMacSizeInBits', CK_ULONG),
    ('ulKeySizeInBits', CK_ULONG),
    ('ulIVSizeInBits', CK_ULONG),
    ('bIsExport', CK_BBOOL),
    ('RandomInfo', CK_SSL3_RANDOM_DATA),
    ('pReturnedKeyMaterial', CK_SSL3_KEY_MAT_OUT_PTR),
]
CK_SSL3_KEY_MAT_PARAMS_PTR = POINTER(CK_SSL3_KEY_MAT_PARAMS)


class CK_TLS_PRF_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_TLS_PRF_PARAMS._pack_ = 1
CK_TLS_PRF_PARAMS._fields_ = [
    ('pSeed', CK_BYTE_PTR),
    ('ulSeedLen', CK_ULONG),
    ('pLabel', CK_BYTE_PTR),
    ('ulLabelLen', CK_ULONG),
    ('pOutput', CK_BYTE_PTR),
    ('pulOutputLen', CK_ULONG_PTR),
]
CK_TLS_PRF_PARAMS_PTR = POINTER(CK_TLS_PRF_PARAMS)


class CK_WTLS_RANDOM_DATA(Structure):
    pass


if 'win' in sys.platform:
    CK_WTLS_RANDOM_DATA._pack_ = 1
CK_WTLS_RANDOM_DATA._fields_ = [
    ('pClientRandom', CK_BYTE_PTR),
    ('ulClientRandomLen', CK_ULONG),
    ('pServerRandom', CK_BYTE_PTR),
    ('ulServerRandomLen', CK_ULONG),
]
CK_WTLS_RANDOM_DATA_PTR = POINTER(CK_WTLS_RANDOM_DATA)


class CK_WTLS_MASTER_KEY_DERIVE_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_WTLS_MASTER_KEY_DERIVE_PARAMS._pack_ = 1
CK_WTLS_MASTER_KEY_DERIVE_PARAMS._fields_ = [
    ('DigestMechanism', CK_MECHANISM_TYPE),
    ('RandomInfo', CK_WTLS_RANDOM_DATA),
    ('pVersion', CK_BYTE_PTR),
]
CK_WTLS_MASTER_KEY_DERIVE_PARAMS_PTR = POINTER(CK_WTLS_MASTER_KEY_DERIVE_PARAMS)


class CK_WTLS_PRF_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_WTLS_PRF_PARAMS._pack_ = 1
CK_WTLS_PRF_PARAMS._fields_ = [
    ('DigestMechanism', CK_MECHANISM_TYPE),
    ('pSeed', CK_BYTE_PTR),
    ('ulSeedLen', CK_ULONG),
    ('pLabel', CK_BYTE_PTR),
    ('ulLabelLen', CK_ULONG),
    ('pOutput', CK_BYTE_PTR),
    ('pulOutputLen', CK_ULONG_PTR),
]
CK_WTLS_PRF_PARAMS_PTR = POINTER(CK_WTLS_PRF_PARAMS)


class CK_WTLS_KEY_MAT_OUT(Structure):
    pass


if 'win' in sys.platform:
    CK_WTLS_KEY_MAT_OUT._pack_ = 1
CK_WTLS_KEY_MAT_OUT._fields_ = [
    ('hMacSecret', CK_OBJECT_HANDLE),
    ('hKey', CK_OBJECT_HANDLE),
    ('pIV', CK_BYTE_PTR),
]
CK_WTLS_KEY_MAT_OUT_PTR = POINTER(CK_WTLS_KEY_MAT_OUT)


class CK_WTLS_KEY_MAT_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_WTLS_KEY_MAT_PARAMS._pack_ = 1
CK_WTLS_KEY_MAT_PARAMS._fields_ = [
    ('DigestMechanism', CK_MECHANISM_TYPE),
    ('ulMacSizeInBits', CK_ULONG),
    ('ulKeySizeInBits', CK_ULONG),
    ('ulIVSizeInBits', CK_ULONG),
    ('ulSequenceNumber', CK_ULONG),
    ('bIsExport', CK_BBOOL),
    ('RandomInfo', CK_WTLS_RANDOM_DATA),
    ('pReturnedKeyMaterial', CK_WTLS_KEY_MAT_OUT_PTR),
]
CK_WTLS_KEY_MAT_PARAMS_PTR = POINTER(CK_WTLS_KEY_MAT_PARAMS)


class CK_CMS_SIG_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_CMS_SIG_PARAMS._pack_ = 1
CK_CMS_SIG_PARAMS._fields_ = [
    ('certificateHandle', CK_OBJECT_HANDLE),
    ('pSigningMechanism', CK_MECHANISM_PTR),
    ('pDigestMechanism', CK_MECHANISM_PTR),
    ('pContentType', CK_UTF8CHAR_PTR),
    ('pRequestedAttributes', CK_BYTE_PTR),
    ('ulRequestedAttributesLen', CK_ULONG),
    ('pRequiredAttributes', CK_BYTE_PTR),
    ('ulRequiredAttributesLen', CK_ULONG),
]
CK_CMS_SIG_PARAMS_PTR = POINTER(CK_CMS_SIG_PARAMS)


class CK_KEY_DERIVATION_STRING_DATA(Structure):
    pass


if 'win' in sys.platform:
    CK_KEY_DERIVATION_STRING_DATA._pack_ = 1
CK_KEY_DERIVATION_STRING_DATA._fields_ = [
    ('pData', CK_BYTE_PTR),
    ('ulLen', CK_ULONG),
]
CK_KEY_DERIVATION_STRING_DATA_PTR = POINTER(CK_KEY_DERIVATION_STRING_DATA)
CK_EXTRACT_PARAMS = CK_ULONG
CK_EXTRACT_PARAMS_PTR = POINTER(CK_EXTRACT_PARAMS)
CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE = CK_ULONG
CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR = POINTER(CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE)
CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE = CK_ULONG
CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR = POINTER(CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE)


class CK_PKCS5_PBKD2_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_PKCS5_PBKD2_PARAMS._pack_ = 1
CK_PKCS5_PBKD2_PARAMS._fields_ = [
    ('saltSource', CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE),
    ('pSaltSourceData', CK_VOID_PTR),
    ('ulSaltSourceDataLen', CK_ULONG),
    ('iterations', CK_ULONG),
    ('prf', CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE),
    ('pPrfData', CK_VOID_PTR),
    ('ulPrfDataLen', CK_ULONG),
    ('pPassword', CK_UTF8CHAR_PTR),
    ('usPasswordLen', CK_ULONG),
]
CK_PKCS5_PBKD2_PARAMS_PTR = POINTER(CK_PKCS5_PBKD2_PARAMS)
CK_OTP_PARAM_TYPE = CK_ULONG
CK_PARAM_TYPE = CK_OTP_PARAM_TYPE


class CK_OTP_PARAM(Structure):
    pass


if 'win' in sys.platform:
    CK_OTP_PARAM._pack_ = 1
CK_OTP_PARAM._fields_ = [
    ('type', CK_OTP_PARAM_TYPE),
    ('pValue', CK_VOID_PTR),
    ('usValueLen', CK_ULONG),
]
CK_OTP_PARAM_PTR = POINTER(CK_OTP_PARAM)


class CK_OTP_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_OTP_PARAMS._pack_ = 1
CK_OTP_PARAMS._fields_ = [
    ('pParams', CK_OTP_PARAM_PTR),
    ('ulCount', CK_ULONG),
]
CK_OTP_PARAMS_PTR = POINTER(CK_OTP_PARAMS)


class CK_OTP_SIGNATURE_INFO(Structure):
    pass


if 'win' in sys.platform:
    CK_OTP_SIGNATURE_INFO._pack_ = 1
CK_OTP_SIGNATURE_INFO._fields_ = [
    ('pParams', CK_OTP_PARAM_PTR),
    ('ulCount', CK_ULONG),
]
CK_OTP_SIGNATURE_INFO_PTR = POINTER(CK_OTP_SIGNATURE_INFO)


class CK_KIP_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_KIP_PARAMS._pack_ = 1
CK_KIP_PARAMS._fields_ = [
    ('pMechanism', CK_MECHANISM_PTR),
    ('hKey', CK_OBJECT_HANDLE),
    ('pSeed', CK_BYTE_PTR),
    ('ulSeedLen', CK_ULONG),
]
CK_KIP_PARAMS_PTR = POINTER(CK_KIP_PARAMS)
if 'win' in sys.platform:
    CK_AES_CTR_PARAMS._pack_ = 1
CK_AES_CTR_PARAMS._fields_ = [
    ('ulCounterBits', CK_ULONG),
    ('cb', CK_BYTE * 16),
]
CK_AES_CTR_PARAMS_PTR = POINTER(CK_AES_CTR_PARAMS)


class CK_CAMELLIA_CTR_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_CAMELLIA_CTR_PARAMS._pack_ = 1
CK_CAMELLIA_CTR_PARAMS._fields_ = [
    ('ulCounterBits', CK_ULONG),
    ('cb', CK_BYTE * 16),
]
CK_CAMELLIA_CTR_PARAMS_PTR = POINTER(CK_CAMELLIA_CTR_PARAMS)


class CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS._pack_ = 1
CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS._fields_ = [
    ('iv', CK_BYTE * 16),
    ('pData', CK_BYTE_PTR),
    ('length', CK_ULONG),
]
CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS_PTR = POINTER(CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS)


class CK_ARIA_CBC_ENCRYPT_DATA_PARAMS(Structure):
    pass


if 'win' in sys.platform:
    CK_ARIA_CBC_ENCRYPT_DATA_PARAMS._pack_ = 1
CK_ARIA_CBC_ENCRYPT_DATA_PARAMS._fields_ = [
    ('iv', CK_BYTE * 16),
    ('pData', CK_BYTE_PTR),
    ('length', CK_ULONG),
]
CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_PTR = POINTER(CK_ARIA_CBC_ENCRYPT_DATA_PARAMS)

__all__ = ['CK_OTP_SIGNATURE_INFO',
           'C_UnwrapKey', 'Int32',
           'C_SetAttributeValue',
           'C_VerifyFinal', 'CK_DATE',
            'CK_WTLS_PRF_PARAMS',
            'C_GetInfo',
            'CK_ATTRIBUTE_PTR', 'CK_VERSION',
            'C_WaitForSlotEvent',
           'CK_VOID_PTR',
            'CK_MECHANISM_INFO',
           'Float64',
           'CK_X9_42_DH_KDF_TYPE',
           'CK_INFO',
           'CK_KIP_PARAMS',
           'CK_OTP_PARAM_PTR', 'CK_X9_42_MQV_DERIVE_PARAMS',
           'C_CloseAllSessions',
           'C_SignInit',
           'CK_CMS_SIG_PARAMS',
           'CK_ECMQV_DERIVE_PARAMS',
           'CK_TLS_PRF_PARAMS_PTR',
           'Word',
           'CK_DES_CTR_PARAMS',
            'CK_OBJECT_HANDLE',
           'CK_MAC_GENERAL_PARAMS',
           'CK_EC_MAC_SCHEME',
           'CK_KDF_PRF_PARAMS', 'CK_ULONG',
           'CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR',
           'Float',
           'CK_DESTROYMUTEX',
           'CK_ECMQV_DERIVE_PARAMS_PTR',
            'SInt8',
            'CK_DES_CTR_PARAMS_PTR',
           'CK_RC5_MAC_GENERAL_PARAMS',
           'CK_SEED_CTR_PARAMS',
           'CK_LKM_TOKEN_ID',
           'CK_CLUSTER_STATE',
           'eInitMsgs', 'CK_FLAGS',
           'CK_HA_MEMBER_PTR',
           'C_Digest',
            'BYTE',
            'C_SignEncryptUpdate',
            'CK_MECHANISM_TYPE_PTR',
           'CK_XOR_BASE_DATA_KDF_PARAMS_PTR', 'CK_SESSION_INFO',
           'CK_WTLS_KEY_MAT_OUT', 'CK_WTLS_KEY_MAT_PARAMS',
           'C_DigestEncryptUpdate', 'UInt16',
           'CK_RSA_PKCS_MGF_TYPE_PTR',
           'CK_SKIPJACK_RELAYX_PARAMS',
            'C_EncryptFinal',
            'CK_EC_KDF_TYPE',
           'CK_CREATEMUTEX',
            'CK_KEY_WRAP_SET_OAEP_PARAMS',
            'CK_SESSION_INFO_PTR',
           'CK_CHAR_PTR',
           'CK_RC5_MAC_GENERAL_PARAMS_PTR',
           'CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE',
           'CK_LKM_TOKEN_ID_PTR',
            'PointerDifference',
           'CK_RC2_MAC_GENERAL_PARAMS', 'CK_SESSION_HANDLE',
           'CK_SLOT_INFO',
           'CK_SESSION_HANDLE_PTR', 'CK_RC2_MAC_GENERAL_PARAMS_PTR',
           'CK_SKIPJACK_PRIVATE_WRAP_PTR',
           'C_SetOperationState',
           'CK_CERTIFICATE_TYPE',
             'CK_OBJECT_CLASS',
            'C_VerifyRecover',
           'C_VerifyRecoverInit',
           'C_DigestKey',
           'CK_KEY_TYPE',
           'CK_RSA_PKCS_PSS_PARAMS',
            'UInt32',
            'CK_AES_XTS_PARAMS_PTR',
            'C_OpenSession',
           'CK_WTLS_RANDOM_DATA_PTR',
           'CK_RSA_PKCS_PSS_PARAMS_PTR', 'CK_RC2_CBC_PARAMS',
            'CK_ARIA_CTR_PARAMS',
           'CK_CAMELLIA_CTR_PARAMS',
           'CK_AES_CBC_PAD_INSERT_PARAMS_PTR',
           'CK_WTLS_KEY_MAT_OUT_PTR',
           'CK_PKCS5_PBKD2_PARAMS',
            'Int64',
           'CK_X9_42_DH2_DERIVE_PARAMS',
           'CK_STATE',
           'C_Verify',
            'C_DecryptFinal',
           'Byte',  'CK_FUNCTION_LIST_PTR',
           'CK_AES_GMAC_PARAMS_PTR', 'CK_CAMELLIA_CTR_PARAMS_PTR',
           'CK_SSL3_RANDOM_DATA',
            'CK_SSL3_KEY_MAT_PARAMS',
           'CK_KIP_PARAMS_PTR',
           'CK_OTP_SIGNATURE_INFO_PTR',
           'CK_WTLS_RANDOM_DATA', 'CK_USHORT',
           'CK_PRF_KDF_PARAMS',
           'CK_X9_42_DH1_DERIVE_PARAMS_PTR',
           'UInt',
           'CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR',
            'fwResultCode',
           'CK_MECHANISM_TYPE',
            'CK_ATTRIBUTE',
            'CK_MECHANISM',
           'C_Encrypt',
           'CK_INFO_PTR', 'CK_ARIA_CTR_PARAMS_PTR',
           'C_SignRecoverInit',
            'CK_BYTE',
           'CK_SSL3_KEY_MAT_OUT',
           'CK_GetTotalOperations',
           'CK_SLOT_INFO_PTR',
           'CK_KEA_DERIVE_PARAMS_PTR',
           'CK_BYTE_PTR',
            'HalfWord',
            'CK_VOID_PTR_PTR',
            'CT_TokenHndle',
            'C_SetPIN',
           'C_GenerateKey',
            'C_InitPIN',
             'CK_ECIES_PARAMS',
           'CK_AES_CTR_PARAMS',
           'CK_LKM_TOKEN_ID_S',
           'CK_X9_42_DH2_DERIVE_PARAMS_PTR',
           'CK_KEY_WRAP_SET_OAEP_PARAMS_PTR',
           'CK_PARAM_TYPE',
           'ResultCodeValue',
           'CK_ECDH1_DERIVE_PARAMS',
           'CK_RC2_PARAMS_PTR', 'CK_WTLS_PRF_PARAMS_PTR',
           'C_FindObjectsFinal',
           'CK_RC2_CBC_PARAMS_PTR',
           'C_Login',
           'C_CreateObject',
           'CK_KEA_DERIVE_PARAMS',
           'UInt64',
           'CK_LONG',
           'CK_OBJECT_HANDLE_PTR',
           'Int',
           'CK_AES_CBC_PAD_EXTRACT_PARAMS',
           'CK_SKIPJACK_RELAYX_PARAMS_PTR',
           'CK_TLS_PRF_PARAMS',
           'CK_SLOT_ID',
           'CT_Token',
           'LastFirmwareCode',
           'C_VerifyInit',
           'CK_SKIPJACK_PRIVATE_WRAP_PARAMS',
            'CK_LOCKMUTEX',
           'CK_EC_ENC_SCHEME', 'CK_MECHANISM_INFO_PTR',
           'CK_OTP_PARAM_TYPE',
           'CK_AES_GMAC_PARAMS',
           'CK_PBE_PARAMS_PTR',
           'CK_ARIA_CBC_ENCRYPT_DATA_PARAMS', 'C_SeedRandom',
           'HANDLE',
           'C_CancelFunction', 'CK_HA_STATUS',
            'C_Initialize',
           'CK_RSA_PKCS_OAEP_PARAMS_PTR',
           'C_InitToken',
           'C_GetSlotList',
           'C_GetMechanismInfo',
           'Boolean',
           'CK_WTLS_KEY_MAT_PARAMS_PTR',
             'CK_RC5_PARAMS',
            'C_SignFinal',
            'CK_AES_CTR_PARAMS_PTR',
            'CK_USHORT_PTR',
           'CK_PKCS5_PBKD2_PARAMS_PTR',
           'CK_AES_CBC_PAD_EXTRACT_PARAMS_PTR',
            'CK_ECDH2_DERIVE_PARAMS_PTR',
            'CK_DES_CBC_ENCRYPT_DATA_PARAMS',
           'CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS',
           'C_GenerateKeyPair',
            'CKA_SIM_AUTH_FORM',
           'CK_HW_FEATURE_TYPE',
            'CK_CLUSTER_STATE_PTR',
           'C_GetTokenInfo',
             'CK_VERSION_PTR',
            'C_DecryptInit',
           'SInt32',
           'CK_ULONG_PTR',
           'CK_KDF_PRF_PARAMS_PTR',
           'CK_AES_CBC_ENCRYPT_DATA_PARAMS',
           'CK_KEY_DERIVATION_STRING_DATA_PTR',
            'ULong',
            'CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR',
           'CK_SLOT_ID_PTR',
           'CK_RV', 'CK_NOTIFY',
           'C_VerifyUpdate',
           'CK_X9_42_MQV_DERIVE_PARAMS_PTR',
           'CK_X9_42_DH_KDF_TYPE_PTR',
           'CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_PTR',
           'C_Sign',
           'CK_X9_42_DH1_DERIVE_PARAMS', 'C_GetFunctionList',
            'C_GetOperationState',
            'CK_BBOOL',
            'CK_ECDH2_DERIVE_PARAMS',
            'CK_OBJECT_CLASS_PTR',
           'CK_RC2_PARAMS',
           'CK_OTP_PARAM',
           'CK_TOKEN_INFO',
           'CK_RSA_PKCS_OAEP_PARAMS', 'CK_SSL3_KEY_MAT_PARAMS_PTR',
           'C_Logout',
            'SizeType',
            'C_Decrypt',
           'CK_EXTRACT_PARAMS_PTR',
           'CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS_PTR',
           'CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR',
           'C_DecryptDigestUpdate', 'CK_AES_XTS_PARAMS',
           'CK_AES_GCM_PARAMS', 'CK_HA_STATE_PTR',
           'CK_XOR_BASE_DATA_KDF_PARAMS', 'C_Finalize',
           'C_GetSlotInfo', 'CK_HA_MEMBER',
            'C_FindObjectsInit',
           'CK_RSA_PKCS_OAEP_SOURCE_TYPE', 'CK_UNLOCKMUTEX',
            'CK_RC5_CBC_PARAMS',
            'CK_KDF_PRF_ENCODING_SCHEME',
           'CK_PBE_PARAMS',
           'CK_USER_TYPE',
           'C_GetMechanismList',
           'CK_WTLS_MASTER_KEY_DERIVE_PARAMS_PTR',
            'C_GetAttributeValue',
           'C_GetFunctionStatus',
           'CK_OTP_PARAMS_PTR',
           'CK_SSL3_MASTER_KEY_DERIVE_PARAMS', 'CK_UTF8CHAR_PTR',
           'swapper',
           'C_WrapKey',
            'CK_ATTRIBUTE_TYPE',
           'CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR',
            'SInt16',
            'C_DestroyObject',
           'CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR',
           'C_GetSessionInfo', 'Int16',
           'CK_SSL3_KEY_MAT_OUT_PTR',
             'CK_CHAR',
            'UInt8',
           'CK_CMS_SIG_PARAMS_PTR',
           'C_DeriveKey',
           'C_DigestUpdate',
            'C_FindObjects', 'SInt64',
           'SInt',
           'CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE',
           'CK_RSA_PKCS_MGF_TYPE', 'CK_EXTRACT_PARAMS',
           'CK_RC5_CBC_PARAMS_PTR',
           'CK_ResetTotalOperations',
            'CK_AES_GCM_PARAMS_PTR',
           'CK_MAC_GENERAL_PARAMS_PTR',
           'CK_TOKEN_INFO_PTR',
           'CK_AES_CBC_PAD_INSERT_PARAMS',
           'CK_KEY_DERIVATION_STRING_DATA', 'CK_MECHANISM_PTR',
           'CK_FUNCTION_LIST',
           'CK_RC5_PARAMS_PTR',
           'CK_WTLS_MASTER_KEY_DERIVE_PARAMS',
           'C_SignUpdate',
           'C_EncryptInit', 'CK_OTP_PARAMS', 'CK_SEED_CTR_PARAMS_PTR',
            'C_DigestFinal',
            'C_CloseSession',
           'CK_EC_DH_PRIMITIVE',
           'CK_FUNCTION_LIST_PTR_PTR',
            'C_DecryptVerifyUpdate',
           'CK_UTF8CHAR',
            'C_DigestInit',
           'C_CopyObject',
           'CK_NOTIFICATION', 'C_SignRecover',
            'C_EncryptUpdate',
            'CK_KDF_PRF_TYPE',
            'CK_ECDH1_DERIVE_PARAMS_PTR',
            'C_DecryptUpdate',
           'Int8',
           'Float32',
           'CK_ECIES_PARAMS_PTR',
           'C_GetObjectSize',
            'DYC_SelfSignX509',
            'DYC_SignX509',
        ]