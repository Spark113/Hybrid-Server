__author__ = 'Ido Kaplan'
from tcp_by_size import recv_by_size, send_with_size
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
#from TCP_AES import send_with_AES, recv_with_AES
import os


def get_user_and_request_code(bdata):
    finish = bdata.find(b'~') + 1
    second = bdata.find(b'~', finish + 1) + 1
    third = bdata.find(b'~', second + 1) + 1

    encrypted_bdata = bdata[third:]
    code = bdata[:finish-1]
    user = bdata[finish:second-1]
    iv = bdata[second:third-1]

    print(f'Bdata: {bdata}\nCode{code}\nUser:{user}\nEn:{encrypted_bdata}')
    return code,user,iv,encrypted_bdata

def send_with_AES(bdata: str|bytearray|bytes, key: str|bytearray|bytes, iv: str|bytearray|bytes):
    """
    sends tcp message with AES encryption.
    using send_with_size from tcp_by_size.
    :param sock: The socket used for sending.
    :param bdata: the data to send.
    :param key: the key for the AES encryption.
    :param iv: the iv for the AES encryption.
    :return: nothing
    """
    #print(f'Sock:{sock}\nbdata:{bdata}\nKey:{key}\nIV:{iv}')
    if not isinstance(bdata, bytes):
        if isinstance(bdata, str):
            bdata = bdata.encode()
        else:
            bdata = bytes(bdata)
    # If the data isn't bytes converts it into bytes
    bdata = pad(bdata, AES.block_size)
    # Adds padding
    if not isinstance(key, bytes):
        if isinstance(key, str):
            key = bytes(key.encode())
        else:
            key = bytes(key)
    # If the key isn't bytes converts it into bytes
    if not isinstance(iv, bytes):
        if isinstance(iv, str):
            iv = bytes(iv.encode())
        else:
            iv = bytes(iv)
    # If the iv isn't bytes converts it into bytes
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
        print('Wrong key length.\n'
              'For AES-128 use a 16 byte key\n'
              'For AES-192 use a 24 byte key\n'
              'For AES-256 use a 32 byte key\n')
    #checks key length
    if len(iv) != 16:
        print('Wrong iv length')
    #checks iv length
    AES_encrypt = AES.new(key, AES.MODE_CBC, iv)
    #creates the AES encryption object
    cypher_data = AES_encrypt.encrypt(bdata)
    # encrypting the bdata
    return cypher_data

def recv_with_AES(key: str|bytearray|bytes, iv: str|bytearray|bytes,bdata: str|bytearray|bytes) -> bytes:
    """
    receives data and decrypts it using AES
    :param sock: the socket used for communication
    :param key: the key that the message was encrypted with
    :param iv: the iv that the message was encrypted with
    :return: the decrypted message
    """
    #print(f'Sock:{sock}\nKey:{key}\nIV:{iv}')

    encrypted_bdata = bdata

    # Receives the message
    if not isinstance(key, bytes):
        if isinstance(key, str):
            key = bytes(key.encode())
        else:
            key = bytes(key)
    # If the key isn't bytes converts it into bytes
    if not isinstance(iv, bytes):
        if isinstance(iv, str):
            iv = bytes(iv.encode())
        else:
            iv = bytes(iv)
    # If the iv isn't bytes converts it into bytes
    AES_decrypt = AES.new(key, AES.MODE_CBC, iv)
    # creates the AES encryption object
    original_bdata = AES_decrypt.decrypt(encrypted_bdata)
    # decrypts the encrypted data
    original_bdata = unpad(original_bdata, AES.block_size)
    return original_bdata

