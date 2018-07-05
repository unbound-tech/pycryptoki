#
# Please note that this file has been modified by Unbound Tech
#
"""
Lookup dictionary for converting CK_ULONG return codes into
their string equivalents -- backwards compatibility
"""
import warnings

warnings.warn("Deprecated! Use 'pypkcs11.lookup_dicts' instead", DeprecationWarning)

# Backwards compatibility for now...
from .lookup_dicts import ret_vals_dictionary
