#
# Please note that this file has been modified by Unbound Tech
#
"""
Exception-s and exception handling code.
"""
import logging

LOG = logging.getLogger(__name__)

class CryptokiException(Exception):
    """
    Base exception class for every custom exception raised by pypkcs11.
    """
    pass


class CryptokiCallException(CryptokiException):
    """Exceptions raised from the result of a PKCS11 call that returned a non-zero
    return code. This will attempt to look up the error code defines for human-readable output.
    """

    def __init__(self, error_code, function_name, arguments):
        """
        :param error_code: The error code of the error
        :param function_name: The name of the function
        :param arguments: The arguments passed into the function
        """
        CryptokiException.__init__()
        self.error_code = error_code
        self.function_name = function_name
        self.arguments = arguments

        if self.error_code in ret_vals_dictionary:
            self.error_string = ret_vals_dictionary[self.error_code]
        else:
            self.error_string = "Unknown Code=" + str(hex(self.error_code))

    def __str__(self):
        data = ("\n\tFunction: {func_name}"
                "\n\tError: {err_string}"
                "\n\tError Code: {err_code}"
                "\n\tArguments:\n{args}").format(func_name=self.function_name,
                                                 err_string=self.error_string,
                                                 err_code=hex(self.error_code),
                                                 args=self.arguments)

        return data
