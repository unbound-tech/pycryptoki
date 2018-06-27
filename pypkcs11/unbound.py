"""
    Interface to the following Unbound vendor-specific functions:

* DYC_SelfSignX509
"""
from ctypes import cast, string_at, c_ubyte
from _ctypes import POINTER

from .conversions import from_bytestring
from .attributes import to_byte_array
from .common_utils import refresh_c_arrays, AutoCArray
from .cryptoki import CK_ULONG, DYC_SelfSignX509, CK_MECHANISM_TYPE
from .defines import CKR_OK


def dyc_self_sign_x509(h_session, h_key, hash_alg, subject, serial=None, days=365):
    """Wrapper for Unbound X509 Self Sign function

    :param int h_session: Current session
    :param int h_key: The key handle to sign with
    :param int hash_alg: Hashing algorithm mechanism type
    :param string subject: Certificate subject string
    :param string serial: Certificate serial number
    :returns: (Retcode, Python bytestring of encrypted data)
    :rtype: tuple

    Call example:
    ret, x509 = dyc_self_sign_x509(session, priv_key, CKM_SHA256, 'CN=some guy, L=around, C=US')
    """

    c_subj, _ = to_byte_array(from_bytestring(subject))
    c_subj = cast(c_subj, POINTER(c_ubyte))
    serial_len = len(serial) if serial != None else 0

    x509 = AutoCArray(ctype=c_ubyte)
    @refresh_c_arrays(1)
    def _self_sign_x509():
        return DYC_SelfSignX509(h_session, h_key, CK_MECHANISM_TYPE(hash_alg),
                                c_subj,
                                serial, CK_ULONG(serial_len),
                                CK_ULONG(days),
                                x509.array, x509.size)
    ret = _self_sign_x509()
    if ret != CKR_OK:
        return ret, None

    x509_pystr = string_at(x509.array, x509.size.contents.value)
    return ret, x509_pystr

