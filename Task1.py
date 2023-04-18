import struct
from Crypto.Cipher import AES
import os

header_size = 54  # bytes
BLOCK_SIZE = 16 #16 Bytes = 128 bits

def pkcs7_padding(input_data):
    padding_length = BLOCK_SIZE - len(input_data) % BLOCK_SIZE
    padding = bytes([padding_length] * padding_length)
    return input_data + padding

def pkcs7_unpadding(input_data):
    padding_length = input_data[-1]
    return input_data[:-padding_length]

def make_key():
    return os.urandom(BLOCK_SIZE)

def make_iv():
    return os.urandom(BLOCK_SIZE)

def ecb_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def cbc_encrypt(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b""
    prev_block = iv
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        block = bytes([block[j] ^ prev_block[j] for j in range(BLOCK_SIZE)])
        encrypted_block = cipher.encrypt(block)
        ciphertext += encrypted_block
        prev_block = encrypted_block
    return ciphertext


def encrypt_ecb(input_file, output_file):
    with open(input_file, "rb") as f:
        bmp_header = f.read(54)
        plaintext = f.read()

    plaintext = pkcs7_padding(plaintext)
    key = make_key()
    ciphertext = b""
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        encrypted_block = ecb_encrypt(key, block)
        ciphertext += encrypted_block

    with open(output_file, "wb") as f:
        f.write(bmp_header)
        f.write(ciphertext)


def encrypt_cbc(input_file, output_file):
    with open(input_file, "rb") as f:
        bmp_header = f.read(54)
        plaintext = f.read()
    plaintext = pkcs7_padding(plaintext)
    key = make_key()
    iv = make_iv()
    ciphertext = cbc_encrypt(key, iv, plaintext)
    with open(output_file, "wb") as f:
        f.write(bmp_header)
        f.write(ciphertext)


input_file = "mustang.bmp"
output_file_ecb = "output_ecb.bmp"
output_file_cbc = "output_cbc.bmp"

# ECB encryption
encrypt_ecb(input_file, output_file_ecb)

# CBC encryption
encrypt_cbc(input_file, output_file_cbc)
