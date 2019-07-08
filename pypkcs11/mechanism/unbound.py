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
Unbound vendor specific mechanisms.
"""
from ctypes import cast, c_void_p
from _ctypes import pointer, sizeof

from ..defines import DYCKM_DERIVE_ECDSA_BIP
from ..cryptoki import DYCK_DERIVE_ECDSA_BIP_PARAMS, CK_ULONG, CK_BBOOL
from .helpers import Mechanism


class EcdsaBipDeriveMechanism(Mechanism):
    """
    ECDSA BIP key derivation mechanism
    Parameters for ECDSA BIP Derive
    :param Boolean isHardened
    :param int childNum: The child derivation index.
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


class EciesMechanism(Mechanism):
    """
    Parameters for ECIES
    :param str AAD: additional authenticated data
    """

    def to_c_mech(self):
        """
        Convert extra parameters to ctypes, then build out the mechanism.

        :return: :class:`~pypkcs11.cryptoki.CK_MECHANISM`
        """
        super(EciesMechanism, self).to_c_mech()

        if 'AAD' in self.params:
            aad = self.params['AAD']
            aadLen = len(aad)
        else:
            aad = None
            aadLen = 0

        self.mech.pParameter = cast(aad, c_void_p)
        self.mech.ulParameterLen = CK_ULONG(aadLen)
        return self.mech
