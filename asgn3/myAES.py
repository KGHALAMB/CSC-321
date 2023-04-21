import struct
from Crypto.Cipher import AES
import os

BLOCK_SIZE = 16 #16 Bytes = 128 bits

#add padding to input data
def pkcs7_padding(input_data):
    padding_length = BLOCK_SIZE - len(input_data) % BLOCK_SIZE
    padding = bytes([padding_length] * padding_length)
    return input_data + padding

#remove padding from input data
def pkcs7_unpadding(input_data):
    padding_length = input_data[-1]
    return input_data[:-padding_length]

#make random key
def make_key():
    return os.urandom(BLOCK_SIZE)

#make random iv
def make_iv():
    return os.urandom(BLOCK_SIZE)

#encrypt plaintext using key and iv in ECB mode
def ecb_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

#encrypt plaintext using key and iv in CBC mode
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

#encrypt input file in ECB Mode and save the result in output file
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


#encrypt input file in CBC Mode and save the result in output file
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
