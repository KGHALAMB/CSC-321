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
    msg = int(plaintext.encode().hex(), 16)
    e = publicKey[0]
    n = publicKey[1]
    #print("original msg: ", plaintext)
    if msg > n:
        raise ValueError
    cipher = pow(msg, e, n)
    return cipher

def rsaDecrypt(privateKey, ciphertext):
    d = privateKey[0]
    n = privateKey[1]
    plain = pow(ciphertext, d, n)
    msg = bytes.fromhex((hex(plain))[2:]).decode()
    #print("plaintext is: ", msg)
    return plain
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
    tamperedEncrypted = encrypted^encrypted
    #bob Decrypts the tampered text and uses the key he gets
    hashedKey = (keyHash(tamperedEncrypted)[:32]).encode()
    msg_byte = ("hi bob").encode('utf-8')
    msg = myAES.cbc_encrypt(hashedKey, AESIv, myAES.pkcs7_padding(msg_byte))
    #mallory takes the cipher text and divides it by 2

    print("The AES Key is this: ", AESKey)
    
    #mallCipher = AES.new(msg, AES.MODE_CBC, AESIv)
    #mallPlainText = (myAES.pkcs7_unpadding(mallCipher.decrypt(msg))).decode()
    return 0

rsaKey = rsaKey(256)
AESKey = myAES.make_key()
AESIv = myAES.make_iv()
#print(keyExchange(AESKey,AESIv,rsaKey))

print("Mallory figured this out: ", keyExchangeMallory(AESKey,AESIv, rsaKey))



