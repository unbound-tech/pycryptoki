
Getting Started
===============


Pypkcs11 can be installed on any machine that has Python installed. Python versions >= 2.7
are supported.::

'PKCS11_LIB' environment variable should contain name of your PKCS#11 library.

Simple Example
--------------

This example will print out information about the given token slot.


    .. code-block:: python

        from pypkcs11.session_management import (c_initialize,
                                                   c_get_info,
                                                   get_firmware_version,
                                                   c_get_token_info,
                                                   c_finalize)


        c_initialize()
        print("C_GetInfo: ")
        print("\n".join("\t{}: {}".format(x, y) for x, y in c_get_info().items()))
        token_info = c_get_token_info(0)
        print("C_GetTokenInfo:")
        print("\n".join("\t{}: {}".format(x, y) for x, y in token_info.items()))
        print("Firmware version: {}".format(get_firmware_version(0)))

        c_finalize()

.. footer:: Please note that this document have been modified by Unbound Tech.

