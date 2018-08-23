#
# Please note that this file has been modified by Unbound Tech
#
"""
Unbound mechanisms.
"""
from ctypes import cast, c_void_p
from _ctypes import pointer, sizeof

from ..defines import DYCKM_DERIVE_ECDSA_BIP
from ..cryptoki import DYCK_DERIVE_ECDSA_BIP_PARAMS, CK_ULONG, CK_BBOOL
from .helpers import Mechanism


class EcdsaBipDeriveMechanism(Mechanism):
    """
    BIP-specific mechanism
    Parameters for ECDSA BIP Derive
    """
    REQUIRED_PARAMS = ["hardened", "ulChildNumber"]

    def __init__(self, isHardened, childNum):
        super(EcdsaBipDeriveMechanism, self).__init__(mech_type=DYCKM_DERIVE_ECDSA_BIP, params={
            'hardened': isHardened, 'ulChildNumber': childNum})

    def to_c_mech(self):
        """
        Create the Param structure, then convert the data into byte arrays.

        :return: :class:`~pypkcs11.cryptoki.CK_MECHANISM`
        """
        super(EcdsaBipDeriveMechanism, self).to_c_mech()
        params = DYCK_DERIVE_ECDSA_BIP_PARAMS()
        params.hardened = CK_BBOOL(self.params['hardened'])
        params.ulChildNumber = CK_ULONG(self.params['ulChildNumber'])
        self.mech.pParameter = cast(pointer(params), c_void_p)
        self.mech.ulParameterLen = CK_ULONG(sizeof(params))
        return self.mech
