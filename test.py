from Crypto.Cipher import AES
import os

HEADER_SIZE = 54  # bytes

def pkcs7_padding(input_data):
    padding_length = BLOCK_SIZE - len(input_data) % BLOCK_SIZE
    padding = bytes([padding_length] * padding_length)
    return input_data + padding

def pkcs7_unpadding(input_data):
    padding_length = input_data[-1]
    return input_data[:-padding_length]

def make_key():
    return os.urandom(BLOCK_SIZE)

def ecb_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

BLOCK_SIZE = 16 #16 Bytes = 128 bits
def encrypt_ecb(input_file, output_file):
    with open(input_file, "rb") as f:
        plaintext = f.read()
    plaintext = pkcs7_padding(plaintext)
    key = make_key()
    ciphertext = b"" #means empty byte string
    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        encrypted_block = ecb_encrypt(key, block)
        ciphertext += encrypted_block
    with open(output_file, "wb") as f:
        f.write(ciphertext)

input_file = "cp-logo.bmp"
output_file_ecb = "output_ecb.bmp"

# ECB encryption
encrypt_ecb(input_file, output_file_ecb)