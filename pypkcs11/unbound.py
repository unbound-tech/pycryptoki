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
    Interface to the following Unbound vendor-specific functions:

* DYC_SelfSignX509
* DYC_SignX509
* DYC_CreateX509Request
"""
from ctypes import cast, string_at, c_ubyte
from _ctypes import POINTER

from .conversions import from_bytestring
from .attributes import to_byte_array
from .common_utils import refresh_c_arrays, AutoCArray
from .cryptoki import CK_ULONG, CK_MECHANISM_TYPE, DYC_SelfSignX509, DYC_SignX509, DYC_CreateX509Request
from .defines import CKR_OK


def dyc_self_sign_x509(h_session, h_key, hash_alg, subject, serial=None, days=365):
    """Wrapper for Unbound X509 Self Sign function

    :param int h_session: Current session
    :param int h_key: The key handle to sign with
    :param int hash_alg: Hashing algorithm mechanism type
    :param string subject: Certificate subject string
    :param bytes serial: Certificate serial number
    :param int days: Number of days
    :returns: (Retcode, Python bytestring of self signed X509 certificate)
    :rtype: tuple

    Call example:
    ret, x509 = dyc_self_sign_x509(session, priv_key, CKM_SHA256, 'CN=some guy, L=around, C=US')
    """

    c_subj, _ = to_byte_array(from_bytestring(subject + '\0'))
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


def dyc_sign_x509(h_session, h_key, x509CA, hash_alg, csr, serial=None, days=365):
    """Wrapper for Unbound X509 Sign function

    :param int h_session: Current session
    :param int h_key: The key handle to sign with
    :param int hash_alg: Hashing algorithm mechanism type
    :param bytes x509CA: CA Certificate
    :param bytes csr: Certificate Sign Request
    :param bytes serial: Certificate serial number
    :returns: (Retcode, Python bytestring of signed X509 certificate)
    :rtype: tuple

    """

    serial_len = len(serial) if serial != None else 0

    x509 = AutoCArray(ctype=c_ubyte)

    @refresh_c_arrays(1)
    def _sign_x509():
        return DYC_SignX509(h_session, h_key,
                            cast(x509CA, POINTER(c_ubyte)
                                 ), CK_ULONG(len(x509CA)),
                            CK_MECHANISM_TYPE(hash_alg),
                            cast(csr, POINTER(c_ubyte)), CK_ULONG(len(csr)),
                            serial, CK_ULONG(serial_len),
                            CK_ULONG(days),
                            x509.array, x509.size)
    ret = _sign_x509()
    if ret != CKR_OK:
        return ret, None

    x509_pystr = string_at(x509.array, x509.size.contents.value)
    return ret, x509_pystr


def dyc_create_x509_request(h_session, h_key, hash_alg, subject):
    """Wrapper for Unbound Create X509 Certificate Signing Request function

    :param int h_session: Current session
    :param int h_key: The key handle to sign with
    :param int hash_alg: Hashing algorithm mechanism type
    :param string subject: Certificate  subject string
    :returns: (Retcode, Python bytestring of X509 CSR)
    :rtype: tuple
    """

    c_subj, _ = to_byte_array(from_bytestring(subject + '\0'))
    c_subj = cast(c_subj, POINTER(c_ubyte))

    x509Req = AutoCArray(ctype=c_ubyte)

    @refresh_c_arrays(1)
    def _self_sign_x509():
        return DYC_CreateX509Request(h_session, h_key, CK_MECHANISM_TYPE(hash_alg),
                                     c_subj,
                                     x509Req.array, x509Req.size)
    ret = _self_sign_x509()
    if ret != CKR_OK:
        return ret, None

    x509_pystr = string_at(x509Req.array, x509Req.size.contents.value)
    return ret, x509_pystr
