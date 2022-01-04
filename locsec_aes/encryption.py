import ast
import logging
import hashlib
import traceback
import sys
from random import randbytes

from Cryptodome.Cipher import AES

from EncryptionException import EncryptionException

'''
LocSec AES encryption chunk:
 
         |_not encrypted_|_________________________________________encrypted__________________________________________|

 size            16                  32                     32                              10485760 (max)
(bytes)  |===============|######################|######################|##############################################|
                ^                    ^                      ^                                  ^
          initial vector     type of encrypted     length of encrypted                   encrypted data
                             data (str, dict,      data (in bytes)
                             object, etc.)
'''

supported_data_types = ["str", "int", "float", "list", "dict", "bytearray"]

default_data_resolution = 256
data_size_max = 10485760  # 10 MiB
key_len = 512
default_encoding = sys.getdefaultencoding()

fe = traceback.format_exc


def encrypt_data(data, encryption_key, initial_vector=None):
    try:

        if len(encryption_key) < 8 or type(encryption_key) is not str:
            raise EncryptionException("Bad encryption key:\n"
                                      "Encryption key should be a string with no less than 8 characters.")

        # Encryption key should be padded to key_len (done by creating SHA256)
        key_raw = pad_enc_key(byteify(encryption_key))

        # This is some magic used by AES256 to encrypt and decrypt (may not be secret or may be like a second password).
        #  in our case it is not secret. This vector should be 16 bytes long
        if initial_vector is None:
            initial_vector = bytearray(randbytes(16))
        aes = AES.new(key_raw, AES.MODE_CBC, initial_vector)

        # This step takes whatever type input data is and converts it to bytearray
        data_byteified = byteify(data)

        # Taking data length and writing it to be encrypted (so that it's easier to depad later)
        data_length = len(data_byteified)
        if data_length > data_size_max:
            raise EncryptionException(
                "Data exceeded maximum size. Max supported data size is {} bytes.".format(data_size_max))
        data_length_raw = pad_data(byteify(data_length), 32)

        # Adding (and padding) data type
        data_type = data.__class__.__name__
        if data_type in supported_data_types:
            data_raw = pad_data(bytearray(data_type, default_encoding), 32)
        else:
            raise EncryptionException("Data type \"{}\" is not supported.".format(data_type))
        # Adding data length
        data_raw.extend(data_length_raw)
        # Adding the data itself
        data_raw.extend(data_byteified)

        # Data to encrypt should be padded too (as AES encrypts by 16-byte chunks)
        #  Data resolution is dynamically calculated to make data 256-divisible (which will make it harder to guess
        #  the size of initial data.
        data_resolution = default_data_resolution
        while data_resolution < data_length + 32:  # +32 is to account for added data type
            data_resolution += default_data_resolution
        # -16 is to account for additional data in each encrypted chunk
        data_padded = pad_data(data_raw, data_resolution - 16)

        # Writing the vector we used above to encrypted data, so that we can decrypt it later
        encrypted_data = initial_vector
        encrypted_data.extend(bytearray(aes.encrypt(data_padded)))
        return encrypted_data
    except Exception:
        logging.exception("Error while encrypting data.")
        raise EncryptionException("Error while encrypting. Check logs")


def decrypt_data_return_raw(data_to_dec, encryption_key):
    if type(data_to_dec) is not bytearray:
        logging.warning("{}: Data to decrypt is not bytearray. Will try to byteify,"
                        " but please pass data as raw bytearray.".format(__file__))
    data_raw = byteify(data_to_dec)
    # Preparing key for use
    key_raw = pad_enc_key(byteify(encryption_key))

    # Getting initial vector (it is first 16 unencrypted bytes)
    init_vector = data_raw[:16]

    # All the encrypted data is everything after initial vector
    encrypted_data = data_raw[16:]

    # Initializing AES and decrypting data
    aes = AES.new(key_raw, AES.MODE_CBC, init_vector)
    decrypted_data = bytearray(aes.decrypt(encrypted_data))
    return decrypted_data


def decrypt_data(data_to_dec, encryption_key):
    try:
        decrypted_data = decrypt_data_return_raw(data_to_dec, encryption_key)

        # Stripping parts of decrypted chunk, finding encrypted data
        data_type = depad_data(decrypted_data[:32]).decode(default_encoding)
        data_length = int(depad_data(decrypted_data[32:64]))
        decrypted_data_raw = decrypted_data[64:64 + data_length]
        # Creating a properly-typed object from decrypted data and returning it
        decrypted_data_prepared = prepare_decrypted_data(data_type, decrypted_data_raw)
        return decrypted_data_prepared
    except Exception:
        logging.exception("Error while decrypting data.")
        raise EncryptionException("Error while decrypting. Check logs")


def pad_enc_key(input_key):
    if type(input_key) is not bytearray:
        raise EncryptionException("Could not pad key: data is not byteified.\n{}".format(fe()))
    try:
        if len(input_key) != key_len:
            sha256 = hashlib.sha256()
            sha256.update(input_key)
            encrypt_key = sha256.digest()
        else:
            encrypt_key = input_key
        return encrypt_key
    except Exception:
        raise EncryptionException("Error while padding encryption key: {}".format(fe()))


def pad_data(data, resolution):
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


def depad_data(data):
    if type(data) is not bytearray:
        raise EncryptionException("Could not depad data: data is not byteified!")
    # Use it carefully, this may destroy data!
    depadded_data = [abyte for abyte in data if abyte.to_bytes(1, sys.byteorder) != b'\x00']
    return bytearray(depadded_data)


def byteify(data):
    match data:
        case str():
            return bytearray(data, default_encoding)
        case int() | float() | list() | dict():
            return bytearray(str(data), default_encoding)
        case bytes():
            return bytearray(data)
        case bytearray():
            return data
        case _:
            raise EncryptionException("Unknown data type passed to prepare for encryption! The type is: {}"
                                      .format(type(data)))


def prepare_decrypted_data(data_type, data):
    match data_type:
        case "str":
            return data.decode(default_encoding)
        case "int":
            return int(data)
        case "float":
            return float(data)
        case "dict" | "list":  # potential bugs???
            return ast.literal_eval(data.decode(default_encoding))
        case "bytearray":
            return bytearray(data)
        case _:
            return EncryptionException(
                "How did you even encrypt this? I don't know such data type: {}".format(data_type))
