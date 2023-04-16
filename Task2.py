import Task1
from Crypto.Cipher import AES
import os

HEADER_SIZE = 54  # bytes
BLOCK_SIZE = 16 #16 Bytes = 128 bits

def submit(input_string):
    res = input_string.replace(";", "%3B")
    res = res.replace("+", "%2B")
    res = "userid=456;userdata=" + res + ";session-id=31337"
    res_byte = res.encode('utf-8')
    padded_res = Task1.pkcs7_padding(res_byte)
    key = Task1.make_key()
    iv = Task1.make_iv()
    return Task1.cbc_encrypt(key,iv,padded_res)

print(submit("You're;the+man now dog!"))
