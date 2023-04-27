from Crypto.Util.number import getPrime
import hashlib
import myAES
from Crypto.Cipher import AES

def rsaKey(bits):
    p = getPrime(bits)
    q = getPrime(bits)
    while p == q:
        q = getPrime(bits)
    n = p * q
    e = 65537
    phi = (p-1)*(q-1)
    d = pow(e,-1,phi)
    publicKey = [e, n]
    privateKey = [d, n]
    return {"publicKey" : publicKey, "privateKey" : privateKey}

def rsaEncrypt(publicKey, plaintext):
    #print("The plaintext is: ", plaintext)
    msg = int(plaintext.encode().hex(), 16)
    e = publicKey[0]
    n = publicKey[1]
    if msg > n:
        raise ValueError
    cipher = pow(msg, e, n)
    return cipher

def rsaDecrypt(privateKey, ciphertext):
    d = privateKey[0]
    n = privateKey[1]
    plain = pow(ciphertext, d, n)
    hex_str = '{:0>2x}'.format(plain)
    msg = bytes.fromhex(hex_str).decode(errors="ignore")
    #print("decrypted: ", msg)
    return msg
def keyHash(key):
    return(hashlib.sha256(str(key).encode()).hexdigest())

def keyExchange(AESKey, AESIv, rsaKey):
    #Alice would be decrypting an AES key that is sent by Bob
    #she uses her private key to decrypt while bob uses the public key to encrypt
    key = rsaDecrypt(rsaKey["privateKey"], rsaEncrypt(rsaKey["publicKey"], str(AESKey)))
    hashedKey = (keyHash(key)[:32]).encode()
    msg_byte = ("hi bob").encode('utf-8')
    msg = myAES.cbc_encrypt(hashedKey, AESIv, myAES.pkcs7_padding(msg_byte))
    return msg

def keyExchangeMallory(AESKey, AESIv, rsaKey):
    #Alice encrypts the AES Key
    encrypted = rsaEncrypt(rsaKey["publicKey"], str(AESKey))
    #mallory tampers with the cipher text that alice makes
    tamperedEncrypted = int(encrypted * 0)
    #bob Decrypts the tampered text and uses the key he gets, mallory knows that the result 
    # Bob will get from RSA decrypt is 0
    key = rsaDecrypt(rsaKey["privateKey"], tamperedEncrypted)
    hashedKey = (keyHash(key)[:32]).encode()
    #mallory at this point knows what the key returned from rsa will be so she can use it
    mallHashedKey = (keyHash('\x00')[:32]).encode()
    msg_byte = ("Hi Bob!").encode('utf-8')
    msg = myAES.cbc_encrypt(hashedKey, AESIv, myAES.pkcs7_padding(msg_byte))
    #mallory can figure out what the encrypted message is, purely through her own hashed key
    mallCipher = AES.new(mallHashedKey, AES.MODE_CBC, AESIv)
    mallPlainText = (myAES.pkcs7_unpadding(mallCipher.decrypt(msg))).decode()
    return mallPlainText
def malloryCausesChaos(AESKey, AESIv, rsaKey):
    #Alice encrypts the AES Key
    encrypted = rsaEncrypt(rsaKey["publicKey"], str(AESKey))
    #mallory tampers with the cipher text that alice makes
    tamperedEncrypted = int(encrypted + 1)
    #bob Decrypts the tampered RSA cipher text, then hashes it into a key
    key = rsaDecrypt(rsaKey["privateKey"], tamperedEncrypted)
    hashedKey = (keyHash(key)[:32]).encode()
    # bob uses the changed key to cbc encrypt 
    msg_byte = ("Hi Bob!").encode('utf-8')
    msg = myAES.cbc_encrypt(hashedKey, AESIv, myAES.pkcs7_padding(msg_byte))
    # The message that alice recieves is decrypted with the AES Key she knows
    realKey = (keyHash(AESKey)[:32]).encode()
    Cipher = AES.new(realKey, AES.MODE_CBC, AESIv)
    scrambledMsg = (myAES.pkcs7_unpadding(Cipher.decrypt(msg))).decode()
    return scrambledMsg


MyRsaKey = rsaKey(256)
AESKey = myAES.make_key()
AESIv = myAES.make_iv()
print("After Alice Sends the text: Hi Bob!\nMallory found the plaintext: ", keyExchangeMallory(AESKey,AESIv, MyRsaKey))

#MyRsaKey = rsaKey(256)
#AESKey = myAES.make_key()
#AESIv = myAES.make_iv()

#keyExchange(AESKey, AESIv, MyRsaKey)
#print("After Mallory attacked the integrity, instead of Hi Bob!, bob recieved: ", malloryCausesChaos(AESKey,AESIv, MyRsaKey))
