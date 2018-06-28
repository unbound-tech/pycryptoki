#
# Please note that this file have been modified by Unbound Tech
#
"""
Methods related to encrypting data/files.
"""
import logging
from _ctypes import POINTER
from ctypes import create_string_buffer, cast, byref, string_at, c_ubyte

from .attributes import Attributes, to_byte_array
from .common_utils import AutoCArray, refresh_c_arrays
from .conversions import from_bytestring
from .cryptoki import CK_ULONG, \
    C_EncryptInit, C_Encrypt
from .cryptoki import C_Decrypt, C_DecryptInit, CK_OBJECT_HANDLE, \
    C_WrapKey, C_UnwrapKey, C_EncryptUpdate, C_EncryptFinal, CK_BYTE_PTR, \
    C_DecryptUpdate, C_DecryptFinal
from .defines import CKR_OK
from .lookup_dicts import ret_vals_dictionary
from .mechanism import parse_mechanism

MAX_BUFFER = 0xffff

LOG = logging.getLogger(__name__)


def c_encrypt(h_session, h_key, data, mechanism, output_buffer=None):
    """Encrypts data with a given key and encryption flavor
    encryption flavors

    .. note:: If data is a list or tuple of strings, multi-part encryption will be used.

    :param int h_session: Current session
    :param int h_key: The key handle to encrypt the data with
    :param data: The data to encrypt, either a bytestring or a list of bytestrings. If this is
        a list a multipart operation will be used

        .. note:: This will be converted to hexadecimal by calling::

                to_hex(from_bytestring(data))

            If you need to pass in raw hex data, call::

                to_bytestring(from_hex(hex-data))


            References:
                * :py:func:`~pypkcs11.conversions.to_hex`
                * :py:func:`~pypkcs11.conversions.from_hex`
                * :py:func:`~pypkcs11.conversions.to_bytestring`
                * :py:func:`~pypkcs11.conversions.from_bytestring`

    :param mechanism: See the :py:func:`~pypkcs11.mechanism.parse_mechanism` function
        for possible values.
    :param list|int output_buffer: Integer or list of integers that specify a size of output 
        buffer to use for an operation. By default will query with NULL pointer buffer
        to get required size of buffer.
    :returns: (Retcode, Python bytestring of encrypted data)
    :rtype: tuple
    """
    mech = parse_mechanism(mechanism)
    # if a list is passed out do an encrypt operation on each string in the list, otherwise just
    # do one encrypt operation
    is_multi_part_operation = isinstance(data, (list, tuple))

    # Initialize encryption
    ret = C_EncryptInit(h_session, byref(mech), CK_ULONG(h_key))
    if ret != CKR_OK:
        return ret, None

    if is_multi_part_operation:
        ret, encrypted_python_string = do_multipart_operation(h_session, C_EncryptUpdate,
                                                              C_EncryptFinal, data, output_buffer)
    else:
        plain_data, plain_data_length = to_byte_array(from_bytestring(data))
        plain_data = cast(plain_data, POINTER(c_ubyte))
        if output_buffer is not None:
            size = CK_ULONG(output_buffer)
            enc_data = AutoCArray(ctype=c_ubyte,
                                  size=size)

            ret = C_Encrypt(h_session,
                            plain_data, plain_data_length,
                            enc_data.array, enc_data.size)

        else:
            enc_data = AutoCArray(ctype=c_ubyte)

            @refresh_c_arrays(1)
            def _encrypt():
                """Closure for getting the buffer size with encrypt."""
                return C_Encrypt(h_session,
                                 plain_data, plain_data_length,
                                 enc_data.array, enc_data.size)

            ret = _encrypt()
        if ret != CKR_OK:
            return ret, None

        # Convert encrypted data into a python string
        encrypted_python_string = string_at(enc_data.array, enc_data.size.contents.value)

    return ret, encrypted_python_string


def _split_string_into_list(python_string, block_size):
    """Splits a string into a list of equal size chunks

    :param python_string: The string to divide
    :param block_size: The size of the blocks to divide the string into
    :returns: A list of strings of block_size

    """
    total_length = len(python_string)
    return [python_string[x:x + block_size] for x in range(0, total_length, block_size)]


def _get_string_from_list(list_of_strings):
    """Takes a list of strings and returns a single concatenated string.

    :param list_of_strings: A list of strings to be concatenated
    :returns: Single string representing the concatenated list

    """
    return b"".join(list_of_strings)


def c_decrypt(h_session, h_key, encrypted_data, mechanism, output_buffer=None):
    """Decrypt given data with the given key and mechanism.

    .. note:: If data is a list or tuple of strings, multi-part decryption will be used.

    :param int h_session: The session to use
    :param int h_key: The handle of the key to use to decrypt
    :param bytes encrypted_data: Data to be decrypted

        .. note:: Data will be converted to hexadecimal by calling::

                to_hex(from_bytestring(data))

            If you need to pass in raw hex data, call::

                to_bytestring(from_hex(hex-data))


            References:
                * :py:func:`~pypkcs11.conversions.to_hex`
                * :py:func:`~pypkcs11.conversions.from_hex`
                * :py:func:`~pypkcs11.conversions.to_bytestring`
                * :py:func:`~pypkcs11.conversions.from_bytestring`

    :param mechanism: See the :py:func:`~pypkcs11.mechanism.parse_mechanism` function
        for possible values.
    :param list|int output_buffer: Integer or list of integers that specify a size of output 
        buffer to use for an operation. By default will query with NULL pointer buffer
        to get required size of buffer.
    :returns: (Retcode, Python bytestring of decrypted data))
    :rtype: tuple
    """
    mech = parse_mechanism(mechanism)
    # Initialize Decrypt
    ret = C_DecryptInit(h_session, mech, CK_ULONG(h_key))
    if ret != CKR_OK:
        return ret, None

    # if a list is passed out do a decrypt operation on each string in the list, otherwise just
    # do one decrypt operation
    is_multi_part_operation = isinstance(encrypted_data, (list, tuple))

    if is_multi_part_operation:
        ret, python_data = do_multipart_operation(h_session, C_DecryptUpdate, C_DecryptFinal,
                                                  encrypted_data, output_buffer)
    else:

        # Get the length of the final data
        # NOTE: The "Conventions for functions returning output in a variable-length buffer"
        # section of the PKCS#11 spec says that the length returned in this
        # case (no output buffer given to C_Decrypt) can exceed the precise
        # number of bytes needed. So the python string that's returned in the
        # end needs to be adjusted based on the second called to C_Decrypt
        # which will have the right length
        c_enc_data, c_enc_data_len = to_byte_array(from_bytestring(encrypted_data))
        c_enc_data = cast(c_enc_data, POINTER(c_ubyte))
        if output_buffer is not None:
            size = CK_ULONG(output_buffer)
            decrypted_data = AutoCArray(ctype=c_ubyte,
                                        size=size)

            ret = C_Decrypt(h_session,
                            c_enc_data, c_enc_data_len,
                            decrypted_data.array, decrypted_data.size)
        else:
            decrypted_data = AutoCArray(ctype=c_ubyte)

            @refresh_c_arrays(1)
            def _decrypt():
                """ Perform the decryption ops"""
                return C_Decrypt(h_session,
                                 c_enc_data, c_enc_data_len,
                                 decrypted_data.array, decrypted_data.size)

            ret = _decrypt()
        if ret != CKR_OK:
            return ret, None

        # Convert the decrypted data to a python readable format
        python_data = string_at(decrypted_data.array, decrypted_data.size.contents.value)

    return ret, python_data


def do_multipart_operation(h_session,
                           c_update_function,
                           c_finalize_function,
                           input_data_list,
                           output_buffer=None):
    """Some code which will do a multipart encrypt or decrypt since they are the same
    with just different functions called

    :param int h_session: Session handle
    :param c_update_function: C_<NAME>Update function to call to update each operation.
    :param c_finalize_function: Function to call at end of multipart operation.
    :param input_data_list: List of data to call update function on.

        .. note:: Data will be converted to hexadecimal by calling::

                to_hex(from_bytestring(data))

            If you need to pass in raw hex data, call::

                to_bytestring(from_hex(hex-data))


            References:
                * :py:func:`~pypkcs11.conversions.to_hex`
                * :py:func:`~pypkcs11.conversions.from_hex`
                * :py:func:`~pypkcs11.conversions.to_bytestring`
                * :py:func:`~pypkcs11.conversions.from_bytestring`

    :param list output_buffer: List of integers that specify a size of output buffers to use
        for multi-part operations. By default will query with NULL pointer buffer
        to get required size of buffer
    """
    python_data = []
    error = None

    for index, chunk in enumerate(input_data_list):
        if output_buffer:
            out_data_len = CK_ULONG(output_buffer[index])
            out_data = cast(create_string_buffer(b'', output_buffer[index]), CK_BYTE_PTR)
        else:
            out_data_len = CK_ULONG()
            out_data = None
        data_chunk, data_chunk_len = to_byte_array(from_bytestring(chunk))
        data_chunk = cast(data_chunk, POINTER(c_ubyte))

        ret = c_update_function(h_session,
                                data_chunk, data_chunk_len,
                                out_data, byref(out_data_len))
        if ret != CKR_OK:
            LOG.debug("%s call on chunk %.20s (%s/%s) Failed w/ ret %s (%s)",
                      c_update_function.__name__,
                      chunk, index + 1, len(input_data_list),
                      ret_vals_dictionary.get(ret, "Unknown retcode"), str(hex(ret)))
            error = ret
            break

        if not output_buffer:
            # Need a second call to actually get the data.
            LOG.debug("Creating cipher data buffer of size %s", out_data_len.value)
            out_data = create_string_buffer(b'', out_data_len.value)
            ret = c_update_function(h_session,
                                    data_chunk, data_chunk_len,
                                    cast(out_data, CK_BYTE_PTR), byref(out_data_len))
            if ret != CKR_OK:
                LOG.debug("%s call on chunk %.20s (%s/%s) Failed w/ ret %s (%s)",
                          c_update_function.__name__,
                          chunk, index + 1, len(input_data_list),
                          ret_vals_dictionary.get(ret, "Unknown retcode"), str(hex(ret)))
                error = ret
                break

        # Get the output
        python_data.append(string_at(out_data, out_data_len.value))

    if error:
        # Make sure we finalize the operation -- don't want to leave any operations active.
        ret = c_finalize_function(h_session,
                                  cast(create_string_buffer(b'', MAX_BUFFER), CK_BYTE_PTR),
                                  CK_ULONG(MAX_BUFFER))
        LOG.debug("%s call after a %s failure returned: %s (%s)",
                  c_finalize_function.__name__,
                  c_update_function.__name__,
                  ret_vals_dictionary.get(ret, "Unknown retcode"), str(hex(ret)))
        return error, b"".join(python_data)

    if output_buffer:
        fin_out_data_len = CK_ULONG(max(output_buffer))
        fin_out_data = create_string_buffer(b"", fin_out_data_len.value)

        ret = c_finalize_function(h_session, cast(fin_out_data, CK_BYTE_PTR),
                                  byref(fin_out_data_len))
        if ret != CKR_OK:
            return ret, b"".join(python_data)
    else:
        # Finalizing multipart decrypt operation
        fin_out_data_len = CK_ULONG()
        # Get buffer size for data
        ret = c_finalize_function(h_session, None, byref(fin_out_data_len))
        if ret != CKR_OK:
            return ret, b"".join(python_data)

        fin_out_data = create_string_buffer(b"", fin_out_data_len.value)
        output = cast(fin_out_data, CK_BYTE_PTR)
        ret = c_finalize_function(h_session, output, byref(fin_out_data_len))
        if ret != CKR_OK:
            return ret, b"".join(python_data)

    if fin_out_data_len.value > 0:
        python_data.append(string_at(fin_out_data, fin_out_data_len.value))

    return ret, b"".join(python_data)


def c_wrap_key(h_session, h_wrapping_key, h_key, mechanism, output_buffer=None):
    """Wrap a key into an encrypted data blob.

    :param int h_session: The session to use
    :param int h_wrapping_key: The handle of the key to use to wrap another key
    :param int h_key: The key to wrap based on the encryption flavor
    :param mechanism: See the :py:func:`~pypkcs11.mechanism.parse_mechanism` function
        for possible values.
    :returns: (Retcode, python bytestring representing wrapped key)
    :rtype: tuple
    """
    mech = parse_mechanism(mechanism)

    if output_buffer is not None:
        size = CK_ULONG(output_buffer)
        wrapped_key = AutoCArray(ctype=c_ubyte,
                                 size=size)
        ret = C_WrapKey(h_session, mech,
                        CK_OBJECT_HANDLE(h_wrapping_key), CK_OBJECT_HANDLE(h_key),
                        wrapped_key.array, wrapped_key.size)
    else:
        wrapped_key = AutoCArray(ctype=c_ubyte)

        @refresh_c_arrays(1)
        def _wrap():
            """  Perform the Wrapping operation"""
            return C_WrapKey(h_session, mech,
                             CK_OBJECT_HANDLE(h_wrapping_key), CK_OBJECT_HANDLE(h_key),
                             wrapped_key.array, wrapped_key.size)

        ret = _wrap()

    if ret != CKR_OK:
        return ret, None

    return ret, string_at(wrapped_key.array, wrapped_key.size.contents.value)


def c_unwrap_key(h_session, h_unwrapping_key, wrapped_key, key_template, mechanism):
    """Unwrap a key from an encrypted data blob.

    :param int h_session: The session to use
    :param int h_unwrapping_key: The wrapping key handle
    :param bytes wrapped_key: The wrapped key

        .. note:: Data will be converted to hexadecimal by calling::

                to_hex(from_bytestring(data))

            If you need to pass in raw hex data, call::

                to_bytestring(from_hex(hex-data))


            References:
                * :py:func:`~pypkcs11.conversions.to_hex`
                * :py:func:`~pypkcs11.conversions.from_hex`
                * :py:func:`~pypkcs11.conversions.to_bytestring`
                * :py:func:`~pypkcs11.conversions.from_bytestring`

    :param dict key_template: The python template representing the new key's template
    :param mechanism: See the :py:func:`~pypkcs11.mechanism.parse_mechanism` function
        for possible values.
    :returns: (Retcode, unwrapped key handle)
    :rtype: tuple
    """
    mech = parse_mechanism(mechanism)
    c_template = Attributes(key_template).get_c_struct()
    byte_wrapped_key, key_len = to_byte_array(from_bytestring(wrapped_key))
    byte_wrapped_key = cast(byte_wrapped_key, CK_BYTE_PTR)
    h_output_key = CK_ULONG()
    ret = C_UnwrapKey(h_session, mech, CK_OBJECT_HANDLE(h_unwrapping_key),
                      byte_wrapped_key, key_len,
                      c_template, CK_ULONG(len(key_template)), byref(h_output_key))

    return ret, h_output_key.value
