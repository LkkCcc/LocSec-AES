import json
import hashlib
import traceback
import sys
from random import randbytes
from hashlib import sha256
from Cryptodome.Cipher import AES

from locsec_aes.logger import get_logger

logger = get_logger()

from locsec_aes.EncryptionException import EncryptionException

encoding = "utf-8"

'''
LocSec AES encryption chunk:
 
         |_not encrypted_|_________________________________________encrypted__________________________________________|

 size            16                  32                     32                        10485760 (10 MiB) (max)
(bytes)  |===============|######################|######################|##############################################|
                ^                    ^                      ^                                  ^
          initial vector    sha256 of the data     length of encrypted                   encrypted data
                                                      data (in bytes)
                             
'''

supported_data_types = ["str", "int", "float", "list", "dict", "bytearray"]

data_hash_header_length = 32
data_length_header_length = 32
encrypted_headers_length = data_hash_header_length + data_length_header_length
initial_vector_length = 16
default_data_resolution = 256
data_size_max = 10485760  # 10 MiB
min_key_length = 8
key_len = 512

default_encoding = sys.getdefaultencoding()

fe = traceback.format_exc


def encrypt_data(data, encryption_key, initial_vector=None):
    """
    Encrypting data. One of two main methods in LocSec.
    :param data: Data to encrypt (preferably a bytearray)
    :param encryption_key: Encryption key
    :param initial_vector: IV for encryption. (Will be autogenerated if not specified)
    :return: Encrypted LocSec chunk
    """
    try:

        if len(encryption_key) < min_key_length or type(encryption_key) is not str:
            raise EncryptionException("Bad encryption key:\n"
                                      "Encryption key should be a string with no less than 8 characters.")

        # Encryption key should be padded to key_len (done by creating SHA256)
        key_raw = _pad_enc_key(_byteify(encryption_key))

        # This is some magic used by AES256 to encrypt and decrypt (may not be secret or may be like a second password).
        #  in our case it is not secret. This vector should be 16 bytes long
        if initial_vector is None:
            initial_vector = bytearray(randbytes(initial_vector_length))
        aes = AES.new(key_raw, AES.MODE_CBC, initial_vector)

        # This step takes whatever type input data is and converts it to bytearray
        data_byteified = _byteify(data)

        # Taking data length and writing it to be encrypted (so that it's easier to depad later)
        data_length = len(data_byteified)
        if data_length > data_size_max:
            raise EncryptionException(
                "Data exceeded maximum size. Max supported data size is {} bytes.".format(data_size_max))
        data_length_raw = _pad_data(_byteify(data_length, True), data_length_header_length)

        # Adding (and padding) data type
        data_raw = bytearray(_sha(data_byteified))
        # Adding data length
        data_raw.extend(data_length_raw)
        # Adding the data itself
        data_raw.extend(data_byteified)

        # Data to encrypt should be padded too (as AES encrypts by 16-byte chunks)
        #  Data resolution is dynamically calculated to make data 256-divisible (which will make it harder to guess
        #  the size of initial data.
        data_resolution = default_data_resolution
        while data_resolution < data_length + initial_vector_length + encrypted_headers_length:
            data_resolution += default_data_resolution
        # -16 is to account for additional data in each encrypted chunk
        data_padded = _pad_data(data_raw, data_resolution - initial_vector_length)

        # Writing the vector we used above to encrypted data, so that we can decrypt it later
        encrypted_data = initial_vector
        encrypted_data.extend(bytearray(aes.encrypt(data_padded)))
        return encrypted_data
    except Exception:
        logger.exception("Error while encrypting data.")
        raise EncryptionException("Error while encrypting. Check logs")


def _decrypt_data_return_raw_wo_headers(data_to_dec, encryption_key):
    """
    :param data_to_dec: Data to decrypt (preferably a bytearray)
    :param encryption_key: Encryption key
    :return: raw decrypted data (just decrypted data, without checksum verification)
    """
    try:
        decrypted_data = _decrypt_data_return_raw(data_to_dec, encryption_key)
        # Stripping parts of decrypted chunk, finding encrypted data
        data_hash = decrypted_data[:data_hash_header_length]
        data_length = int(_depad_data(decrypted_data[data_hash_header_length:encrypted_headers_length]))
        decrypted_data_raw = decrypted_data[encrypted_headers_length:encrypted_headers_length + data_length]
        return data_hash, decrypted_data_raw
    except Exception:
        logger.exception("Error while decrypting data")


def _sha(data):
    sha_obj = sha256()
    sha_obj.update(data)
    return sha_obj.digest()


def _decrypt_data_return_raw(data_to_dec, encryption_key):
    """
    :param data_to_dec: Data to decrypt (preferably a bytearray)
    :param encryption_key: Encryption key
    :return: raw decrypted data (just a full decrypted LocSec chunk)
    """
    if type(data_to_dec) is not bytearray:
        logger.warning("{}: Data to decrypt is not bytearray. Will try to byteify,"
                       " but please pass data as raw bytearray. You passed data as a \"{}\""
                       .format(__file__, data_to_dec.__class__.__name__))

    if len(data_to_dec) == 0:
        return bytearray()
    data_raw = _byteify(data_to_dec)

    # Preparing key for use
    key_raw = _pad_enc_key(_byteify(encryption_key))

    # Getting initial vector (it is first 16 unencrypted bytes)
    init_vector = data_raw[:initial_vector_length]

    # All the encrypted data is everything after initial vector
    encrypted_data = data_raw[initial_vector_length:]

    # Initializing AES and decrypting data
    aes = AES.new(key_raw, AES.MODE_CBC, init_vector)
    decrypted_data = bytearray(aes.decrypt(encrypted_data))
    return decrypted_data


def decrypt_data(data_to_dec, encryption_key, return_raw=False):
    """
    Decrypting data. One of two main methods in LocSec.
    :param data_to_dec: Data to decrypt
    :param encryption_key: Encryption key
    :param return_raw: Whether to return raw (bytearray) data or stringified
    :return: decrypted data (raw or stringified)
    """
    try:
        data_hash, decrypted_data_raw = _decrypt_data_return_raw_wo_headers(data_to_dec, encryption_key)
        decrypted_data_hash = _sha(decrypted_data_raw)
        if not decrypted_data_hash == data_hash:
            raise EncryptionException("Data hash mismatch:\nExpected: {}\nActual:   {}"
                                      .format(data_hash.hex(), decrypted_data_hash.hex()))
        if return_raw:
            return decrypted_data_raw
        else:
            decrypted_data_prepared = bytes(decrypted_data_raw).decode(encoding=encoding)
            return decrypted_data_prepared
    except Exception:
        logger.exception("Error while decrypting data.")
        raise EncryptionException("Error while decrypting. Check logs")


def _pad_enc_key(input_key):
    """
    Padding encryption key by calculating its sha256 if the key is of insufficient length
    :param input_key: key to pad
    :return: sha256 of the key if key is not exactly 32 bytes long or the key itself if it is
    """
    if type(input_key) is not bytearray:
        raise EncryptionException("Could not pad key: data is not byteified.\n{}".format(fe()))
    try:
        if len(input_key) != key_len:
            sha256 = hashlib.sha256(usedforsecurity=True)
            sha256.update(input_key)
            encrypt_key = sha256.digest()
        else:
            encrypt_key = input_key
        return encrypt_key
    except Exception:
        raise EncryptionException("Error while padding encryption key: {}".format(fe()))


def _pad_data(data, resolution):
    """
    Padding data
    :param data: data to pad
    :param resolution: needed length of output
    :return: padded data
    """
    if type(data) is not bytearray:
        raise EncryptionException("Could not pad data: data is not byteified!")
    if len(data) > resolution:
        raise EncryptionException("Could not pad data: data is bigger than resolution!")
    try:
        data_length = len(data)
        pad_length = resolution - (data_length % resolution)
        data.extend(bytearray(pad_length))
        return data
    except Exception:
        raise EncryptionException("Error while padding data to encrypt: {}".format(fe()))


def _depad_data(data):
    """
    Depadding data (Dangerous!)
    :param data: data to depad
    :return: depadded data
    """
    if type(data) is not bytearray:
        raise EncryptionException("Could not depad data: data is not byteified!")
    # Use it carefully, this may destroy data!
    depadded_data = [abyte for abyte in data if abyte.to_bytes(1, sys.byteorder) != b'\x00']
    return bytearray(depadded_data)


def _byteify(data, no_warnings=False):
    """
    Casting input data to bytearray
    :param data: data to byteify
    :return: data as bytearray
    """
    if not no_warnings and not isinstance(data, str) and not isinstance(data, bytes) and not isinstance(data, bytearray):
        logger.warning("{}: Data to encrypt is not a string or binary. Will try to byteify,"
                       " but please pass data as a string or binary. You passed data as a \"{}\""
                       .format(__file__, data.__class__.__name__))
    match data:
        case str():
            return bytearray(data, encoding)
        case int() | float():
            return bytearray(str(data), encoding)
        case list() | dict():
            return bytearray(json.dumps(data), encoding)
        case bytes():
            return bytearray(data)
        case bytearray():
            return data
        case _:
            raise EncryptionException("Unknown data type passed to prepare for encryption! The type is: \"{}\""
                                      .format(type(data)))
