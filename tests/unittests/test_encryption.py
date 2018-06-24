"""
Unit tests for encryption.py
"""
from string import ascii_letters

from hypothesis import given
from hypothesis.strategies import text, integers, data, lists
from six import b

import pypkcs11.encryption as encrypt


class TestEncryption(object):

    @given(data())
    def test_split_string_into_list(self, data):
        """
        _split_string_into_list() w/ random text and block size
        :param data:
        """
        txt = data.draw(text(alphabet=ascii_letters, min_size=1))
        block = data.draw(integers(min_value=1, max_value=len(txt)))

        txt_list = [txt[i:i + block] for i in range(0, len(txt), block)]
        assert encrypt._split_string_into_list(txt, block) == txt_list

    @given(lists(elements=text(alphabet=ascii_letters), min_size=1))
    def test_get_string_from_list(self, list_val):
        """
        _get_string_from_list w/ list of random text
        :param list_val: list of random text
        """
        list_val = [b(x) for x in list_val]
        assert encrypt._get_string_from_list(list_val) == b"".join(list_val)

