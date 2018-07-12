#
# Please note that this file has been modified by Unbound Tech
#
"""
Utility functions for testing
"""
import os
from pypkcs11.defines import CKA_TOKEN


def get_session_template(default_template):
    """
    Set CKA_TOKEN to false on a template, so that it will be cleaned up on the
    session close.
    """
    default_template.copy()
    default_template[CKA_TOKEN] = False
    return default_template


def get_data_file(filename):
    """
    Get absolute path to filename. Uses current directory as basis to find the testdata folder.

    :param str filename: Filename to append
    :return: full path to file
    """
    return os.path.join(os.path.split(os.path.abspath(__file__))[0], "testdata", filename)
