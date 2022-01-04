import json
import os
import sys
from random import random

import pytest

from locsec_aes.EncryptionException import EncryptionException
from locsec_aes.encryption import encrypt_data, decrypt_data

default_encoding = sys.getdefaultencoding()
enc_key = "Ia$&0f^%n2ERUc^beinHU8pXSLR@ir@*h392xdtStpeEy*tJEO"
test_data_default = "abcdef_)1245%#@!()&%"


def test_int_1():
    test_data = 1
    encrypted = encrypt_data(test_data, enc_key)
    assert decrypt_data(encrypted, enc_key) == test_data


def test_int_2():
    test_data = -1000000000
    encrypted = encrypt_data(test_data, enc_key)
    assert decrypt_data(encrypted, enc_key) == test_data


def test_float_1():
    test_data = 1.1
    encrypted = encrypt_data(test_data, enc_key)
    assert decrypt_data(encrypted, enc_key) == test_data


def test_float_2():
    test_data = -1.1111
    encrypted = encrypt_data(test_data, enc_key)
    assert decrypt_data(encrypted, enc_key) == test_data


def test_float_3():
    test_data = 1.121312312312312312312
    encrypted = encrypt_data(test_data, enc_key)
    assert decrypt_data(encrypted, enc_key) == test_data


def test_string_1():
    test_data = "['A', 'B', 'C', ' D']"
    encrypted = encrypt_data(test_data, enc_key)
    assert decrypt_data(encrypted, enc_key) == test_data


def test_string_2():
    test_data = ""
    encrypted = encrypt_data(test_data, enc_key)
    assert decrypt_data(encrypted, enc_key) == test_data


def test_size_max():
    test_data = bytearray(os.urandom(10485760))
    encrypted = encrypt_data(test_data, enc_key)
    assert decrypt_data(encrypted, enc_key) == test_data


def test_size_too_big():
    with pytest.raises(EncryptionException):
        test_data = bytearray(os.urandom(10485761))
        encrypt_data(test_data, enc_key)


def test_list_1():
    test_data = ["a", "b", "c"]
    encrypted = encrypt_data(test_data, enc_key)
    decrypted_data = decrypt_data(encrypted, enc_key)
    test_data_json = json.dumps(test_data)
    decrypted_data_json = json.dumps(decrypted_data)
    assert test_data_json == decrypted_data_json


def test_list_2():
    test_data = ["a", "b", "c", ["a", "b", "c", ["a", "b", "c", ["a", "b", "c", ["a", "b", "c"]]]]]
    encrypted = encrypt_data(test_data, enc_key)
    decrypted_data = decrypt_data(encrypted, enc_key)
    test_data_json = json.dumps(test_data)
    decrypted_data_json = json.dumps(decrypted_data)
    assert test_data_json == decrypted_data_json


def test_list_3():
    test_data = ["a", "b", "c", ["a", "b", "c", ["a", "b", "c", ["a", "b", "c", ["a", "b", "c",
                                                                                 {"sdfds": [112], "zxz": "azzf",
                                                                                  "aaa": {"aa": ["zz"]}}]]]]]
    encrypted = encrypt_data(test_data, enc_key)
    decrypted_data = decrypt_data(encrypted, enc_key)
    test_data_json = json.dumps(test_data)
    decrypted_data_json = json.dumps(decrypted_data)
    assert test_data_json == decrypted_data_json


def test_dict_1():
    test_data = {"a": "b", "c": "d"}
    encrypted = encrypt_data(test_data, enc_key)
    decrypted_data = decrypt_data(encrypted, enc_key)
    test_data_json = json.dumps(test_data)
    decrypted_data_json = json.dumps(decrypted_data)
    assert test_data_json == decrypted_data_json


def test_dict_2():
    test_data = {"a": ["b", "c", "d"], "e": "f", "g": {"h": "i", "j": {"k": "l", "m": ["n"]}}}
    encrypted = encrypt_data(test_data, enc_key)
    decrypted_data = decrypt_data(encrypted, enc_key)
    test_data_json = json.dumps(test_data)
    decrypted_data_json = json.dumps(decrypted_data)
    assert test_data_json == decrypted_data_json


def test_dict_3():
    test_data = {
        "_id": "61d4b8e171679257734f1f96",
        "index": 0,
        "guid": "9f10aed9-3b94-40ec-a410-057b954f0d48",
        "isActive": False,
        "balance": "$1,987.57",
        "picture": "http://placehold.it/32x32",
        "age": 31,
        "eyeColor": "green",
        "name": "Moody Spence",
        "gender": "male",
        "company": "DEMINIMUM",
        "email": "moodyspence@deminimum.com",
        "phone": "+1 (984) 574-2514",
        "address": "101 Bushwick Place, Robbins, Virgin Islands, 3479",
        "about": "Culpa eu proident aliquip magna dolore ullamco. Ullamco duis dolor cupidatat aliquip veniam ullamco"
                 " cillum elit officia. Aliqua duis ut occaecat minim. Reprehenderit officia consectetur culpa occaecat"
                 " amet anim proident nisi incididunt. Sunt occaecat adipisicing Lorem et est velit proident nisi."
                 " Consequat sit ea nisi excepteur deserunt nisi est.\r\n",
        "registered": "2016-11-16T04:30:22 -03:00",
        "latitude": 81.542216,
        "longitude": -159.105949,
        "tags": [
            "dolore",
            "voluptate",
            "do",
            "et",
            "ex",
            "nostrud",
            "cupidatat"
        ],
        "friends": [
            {
                "id": 0,
                "name": "Janie Moss"
            },
            {
                "id": 1,
                "name": "Hampton Franks"
            },
            {
                "id": 2,
                "name": "Minerva Watson"
            }
        ],
        "greeting": "Hello, Moody Spence! You have 3 unread messages.",
        "favoriteFruit": "banana"
    }
    encrypted = encrypt_data(test_data, enc_key)
    decrypted_data = decrypt_data(encrypted, enc_key)
    test_data_json = json.dumps(test_data)
    decrypted_data_json = json.dumps(decrypted_data)
    assert test_data_json == decrypted_data_json


def test_bad_data_type():
    with pytest.raises(EncryptionException):
        test_data = random
        encrypt_data(test_data, enc_key)


def test_decrypting_broken_data():
    with pytest.raises(EncryptionException):
        decrypt_data("dsfsdfsdfsdfsdfsfsdfsd", enc_key)


def test_bad_key_1():
    with pytest.raises(EncryptionException):
        test_data = test_data_default
        encrypt_data(test_data, "")


def test_bad_key_2():
    with pytest.raises(EncryptionException):
        test_data = test_data_default
        encrypt_data(test_data, "fdsfds")


def test_bad_key_3():
    with pytest.raises(EncryptionException):
        test_data = test_data_default
        encrypted = encrypt_data(test_data, ["fdsfds", "dfsdfsdf"])
        assert decrypt_data(encrypted, enc_key) == test_data


def test_no_data():
    test_data = bytearray()
    encrypted = encrypt_data(test_data, enc_key)
    assert decrypt_data(encrypted, enc_key) == test_data
