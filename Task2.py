import Task1
from Crypto.Cipher import AES
import os

HEADER_SIZE = 54  # bytes
BLOCK_SIZE = 16 #16 Bytes = 128 bits
key = Task1.make_key()
iv = Task1.make_iv()

def submit(input_string, key, iv):
    res = input_string.replace(";", "%3B")
    res = res.replace("=", "%3D")
    res = "userid=456;userdata=" + res + ";session-id=31337"
    res_byte = res.encode('utf-8')
    padded_res = Task1.pkcs7_padding(res_byte)
    return Task1.cbc_encrypt(key,iv,padded_res)

def verify(input_string, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = (Task1.pkcs7_unpadding(cipher.decrypt(input_string)))
    print("plaintext: ", plaintext)
    res = str(plaintext).find(";admin=true;")
    if res == -1:
        return False
    else:
        return True

def byteFlip(cipher_text):
    cipher_text = bytearray(cipher_text)
    cipher_text[4] = ord(chr(cipher_text[4])) ^ ord(";") ^ ord("#")
    cipher_text[10] = ord(chr(cipher_text[10])) ^ ord("=") ^ ord("^")
    #cipher_text[15] = ord(chr(cipher_text[15])) ^ ord(";") ^ ord("#")
    cipher_text = bytes(cipher_text)
    return cipher_text


print(verify(submit("#admin^true#", key, iv),key,iv))
print(verify(byteFlip(submit("#admin^true", key, iv)), key, iv))

#userid=456;userdata=#admin^true#;session-id=31337

#print(verify(submit(";admin=true;", key, iv),key,iv))
