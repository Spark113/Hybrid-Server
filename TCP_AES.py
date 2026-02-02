from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64



def Encrypt_AES(bdata: str | bytearray | bytes, key: str | bytearray | bytes, iv: str | bytearray | bytes):
    """
    Encrypts data using AES encryption.

    :param bdata: The data to encrypt.
    :param key: The key for the AES encryption (must be 16, 24, or 32 bytes).
    :param iv: The initialization vector for the AES encryption (must be 16 bytes).
    :return: The encrypted data.
    """
    # Ensure data is in bytes format
    if not isinstance(bdata, bytes):
        if isinstance(bdata, str):
            bdata = bdata.encode('utf-8')
        else:
            bdata = bytes(bdata)

    # Ensure key is in bytes format and valid length
    if not isinstance(key, bytes):
        if isinstance(key, str):
            key = key.encode('utf-8')
        else:
            key = bytes(key)

    if len(key) not in [16, 24, 32]:
        raise ValueError('Key length must be 16, 24, or 32 bytes (for AES-128, AES-192, or AES-256)')

    # Ensure iv is in bytes format and valid length
    if not isinstance(iv, bytes):
        if isinstance(iv, str):
            iv = iv.encode('utf-8')
        else:
            iv = bytes(iv)

    if len(iv) != 16:
        raise ValueError('IV length must be 16 bytes')

    # Apply padding and verify it's correctly padded to block size
    padded_data = pad(bdata, AES.block_size)

    # Double-check padding is correct (data length is multiple of block size)
    if len(padded_data) % AES.block_size != 0:
        # If somehow padding failed, manually add padding to reach block size
        padding_needed = AES.block_size - (len(padded_data) % AES.block_size)
        padded_data += bytes([padding_needed]) * padding_needed

    # Create cipher and encrypt data
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(padded_data)

    return encrypted_data


def Decrypt_AES(key: str | bytearray | bytes, iv: str | bytearray | bytes, bdata: str | bytearray | bytes) -> bytes:
    """
    Decrypts data using AES encryption.

    :param key: The key that the message was encrypted with.
    :param iv: The iv that the message was encrypted with.
    :param bdata: The encrypted data.
    :return: The decrypted message.
    """
    try:
        # Ensure key is in bytes format and valid length
        if not isinstance(key, bytes):
            if isinstance(key, str):
                key = key.encode('utf-8')
            else:
                key = bytes(key)

        if len(key) not in [16, 24, 32]:
            raise ValueError('Key length must be 16, 24, or 32 bytes')

        # Ensure iv is in bytes format and valid length
        if not isinstance(iv, bytes):
            if isinstance(iv, str):
                iv = iv.encode('utf-8')
            else:
                iv = bytes(iv)

        if len(iv) != 16:
            raise ValueError('IV length must be 16 bytes')

        # Create cipher and decrypt data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(bdata)

        # Remove padding
        try:
            unpadded_data = unpad(decrypted_data, AES.block_size)
            return unpadded_data
        except ValueError as e:
            print(f"Unpadding error: {e}")
            # Try a more lenient approach to unpadding if standard method fails
            padding_value = decrypted_data[-1]
            if 0 < padding_value <= AES.block_size:
                # Check if the padding looks valid
                if all(b == padding_value for b in decrypted_data[-padding_value:]):
                    return decrypted_data[:-padding_value]

            # If we can't unpad, return the raw decrypted data with a warning
            print("Warning: Could not properly unpad data. Returning raw decrypted data.")
            return decrypted_data

    except Exception as e:
        print(f"Decryption error: {e}")
        raise