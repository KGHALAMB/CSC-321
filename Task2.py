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
    plaintext = (Task1.pkcs7_unpadding(cipher.decrypt(input_string))).decode('utf-8')
    plaintext = replaceURL(plaintext)
    #print(plaintext)
    res = plaintext.find(";admin=true;")
    if res == -1:
        return False
    else:
        return True
    
def replaceURL(cipher_text):
    cipher_text = cipher_text.replace("%3D", "=")
    cipher_text = cipher_text.replace("%3B", ";")
    return cipher_text

def byteFlip(cipher_text):
    print(cipher_text)


#byteFlip(submit("userid=456;userdata=You’re the man now, dog;session-id=31337", key, iv))
print(verify(submit("userid=456;userdata=You’re the man now, dog;session-id=31337", key, iv),key,iv))
print(verify(submit("userid=456;userdata=You’re the man now, dog;session-id=31337;admin=true", key, iv),key,iv))
