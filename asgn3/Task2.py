from Crypto.Cipher import AES
import hashlib
import myAES
import secrets

def keyExchange(q, alpha):
    Xa = secrets.randbelow(q) + 1
    Xb = secrets.randbelow(q) + 1

    #Ya = Alice public key
    Ya = alpha^(Xa) % q
    #Yb = Bob public key
    Yb = alpha^Xb % q

    #Mallory intercepts
    Ya = q
    Yb = q

    #Alice and Bob compute shared secret key
    keyA = (Yb)^Xa % q
    keyB = (Ya)^Xb % q

    #Aice and Bob encrypt keys
    hashedKeyA = (keyHash(keyA)[:32]).encode()
    hashedKeyB = (keyHash(keyB)[:32]).encode()

    #print("A:", hashedKeyA)
    #print("B:", hashedKeyB)

    #Alice encrypts message for Bob
    iv = myAES.make_iv()
    msgA_byte = ("hi bob").encode('utf-8')
    msgA = myAES.cbc_encrypt(hashedKeyA, iv, myAES.pkcs7_padding(msgA_byte))

    #Bob decrypts message from Alice
    cipherB = AES.new(hashedKeyA, AES.MODE_CBC, iv)
    plaintextB = (myAES.pkcs7_unpadding(cipherB.decrypt(msgA))).decode()
    print("Bob received: ", plaintextB)

    #Mallory intercepts message from Alice and decrypts it
    cipherB = AES.new(hashedKeyA, AES.MODE_CBC, iv)
    plaintextB = (myAES.pkcs7_unpadding(cipherB.decrypt(msgA))).decode()
    print("Mallory intercepted and decrypted: ", plaintextB)

    #Mallory encrypts message for Alice
    msgM_byte = ("Ay alice, this is Mallory").encode('utf-8')
    msgM = myAES.cbc_encrypt(hashedKeyA, iv, myAES.pkcs7_padding(msgM_byte))

    #Alice decrypts message from Mallory
    cipherA = AES.new(hashedKeyA, AES.MODE_CBC, iv)
    plaintextA = (myAES.pkcs7_unpadding(cipherA.decrypt(msgM))).decode()
    print("Alice received: ", plaintextA)

def keyExchange2(q, alpha):
    Xa = secrets.randbelow(q) + 1
    Xb = secrets.randbelow(q) + 1

    #Ya = Alice public key
    Ya = alpha^(Xa) % q
    #Yb = Bob public key
    Yb = alpha^Xb % q

    #Mallory intercepts
    alpha = 1

    #Alice and Bob compute shared secret key
    keyA = (Yb)^Xa % q
    keyB = (Ya)^Xb % q

    #Aice and Bob encrypt keys
    hashedKeyA = (keyHash(keyA)[:32]).encode()
    hashedKeyB = (keyHash(keyB)[:32]).encode()

    #print("A:", hashedKeyA)
    #print("B:", hashedKeyB)

    #Alice encrypts message for Bob
    iv = myAES.make_iv()
    msgA_byte = ("hi bob").encode('utf-8')
    msgA = myAES.cbc_encrypt(hashedKeyA, iv, myAES.pkcs7_padding(msgA_byte))

    #Bob decrypts message from Alice
    cipherB = AES.new(hashedKeyA, AES.MODE_CBC, iv)
    plaintextB = (myAES.pkcs7_unpadding(cipherB.decrypt(msgA))).decode()
    print("Bob received: ", plaintextB)

    #Mallory intercepts message from Alice and decrypts it
    cipherB = AES.new(hashedKeyA, AES.MODE_CBC, iv)
    plaintextB = (myAES.pkcs7_unpadding(cipherB.decrypt(msgA))).decode()
    print("Mallory intercepted and decrypted: ", plaintextB)

    #Mallory encrypts message for Alice
    msgM_byte = ("Ay alice, this is Mallory").encode('utf-8')
    msgM = myAES.cbc_encrypt(hashedKeyA, iv, myAES.pkcs7_padding(msgM_byte))

    #Alice decrypts message from Mallory
    cipherA = AES.new(hashedKeyA, AES.MODE_CBC, iv)
    plaintextA = (myAES.pkcs7_unpadding(cipherA.decrypt(msgM))).decode()
    print("Alice received: ", plaintextA)


def keyHash(key):
    return(hashlib.sha256(str(key).encode()).hexdigest())


def keyExchangeBig(q, alpha):
    #Xa = key for A
    Xa = 6
    Ya = alpha^(Xa) % q
    #Xb = key for B
    Xb = 15
    Yb = alpha^Xb % q
    
    #print("The Key for A", Xa)
    #print("The Key for B", Xb)
    #print("Key By user A", (Yb)^Xa % q)
    #print("Key By user B", (Ya)^Xb % q)

    #Key by user A
    keyA = (Yb)^Xa % q
    #Key by user B
    keyB = (Ya)^Xb % q
    hashedKeyA = (keyHash(keyA)[:32]).encode()
    hashedKeyB = (keyHash(keyB)[:32]).encode()
    #print("A:", hashedKeyA)
    #print("B:", hashedKeyB)
    msgA_byte = ("hi bob").encode('utf-8')
    msgB_byte = ("hi alice").encode('utf-8')
    iv = myAES.make_iv()
    msgA = myAES.cbc_encrypt(hashedKeyA, iv, myAES.pkcs7_padding(msgA_byte))
    msgB = myAES.cbc_encrypt(hashedKeyB, iv, myAES.pkcs7_padding(msgB_byte))
    cipherA = AES.new(hashedKeyA, AES.MODE_CBC, iv)
    plaintextA = (myAES.pkcs7_unpadding(cipherA.decrypt(msgB))).decode()
    cipherB = AES.new(hashedKeyB, AES.MODE_CBC, iv)
    plaintextB = (myAES.pkcs7_unpadding(cipherB.decrypt(msgA))).decode()
    print(plaintextA)
    print(plaintextB)

#keyExchange(37, 5)

BigQ = "B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371"
BigQ = int((BigQ.replace(" ", "")), 16)

BigA = "A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507FD6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28AD662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24855E6EEB 22B3B2E5"
BigA = int((BigA.replace(" ", "")), 16)

keyExchange(BigQ, BigA)

keyExchange2(BigQ, BigA)

