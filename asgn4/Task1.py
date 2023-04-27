import hashlib
from Crypto.Cipher import AES
import random
import time

def birthdayAttack(size):
    hashes = {}
    start_time = time.time()
    attempts = 0
    while True:
        if attempts % 100000 == 0:
            print(attempts)
        #take a random string and hash it
        input_str = str(random.random())
        hash_str = keyHash(input_str, size)
        #if the string I just hashed is in the dict, 
        if hash_str in hashes and input_str != hashes[hash_str]:
            #print the collision strings and break
            print(f"Collision found for inputs {input_str} and {hashes[hash_str]}")
            #print(hash_str)
            #print(attempts)
            break
        #otherwise add the input string to the dictionary with the hash name
        hashes[hash_str] = input_str
        attempts += 1
    end_time = time.time() - start_time
    print(end_time)
    print(attempts, "attempts")
    
def keyHash(key, size):
    return((hashlib.sha256(str(key).encode()).hexdigest())[0:size])

birthdayAttack(12)