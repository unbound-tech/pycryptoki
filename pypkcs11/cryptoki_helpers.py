"""
Helper functions to get us access to the PKCS11 library.
"""
import logging
import os
import struct
import sys
from ctypes import CDLL

from .exceptions import CryptokiException

LOG = logging.getLogger(__name__)

IS_64B = 8 * struct.calcsize("P") == 64


class CryptokiConfigException(CryptokiException):
    """
    Exception raised when we fail to determine the PKCS11 library location
    """
    pass

class CryptokiDLLException(Exception):
    """Custom exception class used to print an error when a call to the Cryptoki DLL failed.
    The late binding makes debugging a little bit more difficult because function calls
    have to pass through an additional layer of abstraction. This custom exception prints
    out a quick message detailing exactly what function failed.


    """

    def __init__(self, additional_info, orig_error):
        self.msg = additional_info
        self.original_error = orig_error

    def __str__(self):
        return self.msg + "\n" + str(self.original_error)


class CryptokiDLLSingleton(object):
    """A singleton class which holds an instance of the loaded cryptoki DLL object."""

    _instance = None
    loaded_dll_library = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(CryptokiDLLSingleton, cls).__new__(cls, *args, **kwargs)

            dll_path = os.environ['PKCS11_LIB']
            cls._instance.dll_path = dll_path
            if 'win' in sys.platform and IS_64B:
                import ctypes
                cls._instance.loaded_dll_library = ctypes.WinDLL(dll_path)
            else:
                cls._instance.loaded_dll_library = CDLL(dll_path)
        return cls._instance

    def get_dll(self):
        """Get the loaded library (parsed from crystoki.ini/Chrystoki.conf)"""
        if self.loaded_dll_library is None or self.loaded_dll_library == "":
            raise CryptokiException("Failed to load dll")
        return self.loaded_dll_library


def log_args(funcname, args):
    """Log function name & arguments for a cryptoki ctypes call.
    
    :param str funcname: Function name
    :param tuple args: Arguments to be passed to ctypes function.
    """
    log_msg = "Cryptoki call: {}({})".format(funcname,
                                             ", ".join(str(arg) for arg in args))
    LOG.debug(log_msg)


def make_late_binding_function(function_name):
    """A function factory for creating a function that will bind to the cryptoki
    DLL only when the function is called.

    :param function_name:

    """

    def cryptoki_function(*args):
        """

        :param *args:
        :param **kwargs:

        """
        late_binded_function = getattr(CryptokiDLLSingleton().get_dll(), function_name)
        late_binded_function.restype = cryptoki_function.restype
        late_binded_function.argtypes = cryptoki_function.argtypes

        log_args(function_name, args)
        try:
            return_value = late_binded_function(*args)
            return return_value
        except Exception as e:
            raise CryptokiDLLException("Call to '{}({})' "
                                       "failed.".format(function_name,
                                                        ", ".join([str(arg) for arg in args])), e)

    cryptoki_function.__name__ = function_name
    return cryptoki_function
