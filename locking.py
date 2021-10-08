# Inspired from http://coding4streetcred.com/blog/post/Asymmetric-Encryption-Revisited-(in-PyCrypto)
# PyCrypto docs available at https://www.dlitz.net/software/pycrypto/api/2.6/

from Crypto import Random
from Crypto.PublicKey import RSA
import base64

p = 512
q = 23

def generate_keys():
        # RSA modulus length must be a multiple of 256 and >= 1024
        modulus_length = p*q # use larger value in production
        privatekey = RSA.generate(modulus_length, Random.random.randint().read)
        publickey = privatekey.publickey()
        return privatekey, publickey

def encrypt_message(a_message , publickey):
	encrypted_msg = publickey.encrypt(a_message.encode("utf-8"), publickey)[0]
	encoded_encrypted_msg = base64.b64encode(encrypted_msg) # base64 encoded strings are database friendly
	return encoded_encrypted_msg

def decrypt_message(encoded_encrypted_msg, privatekey):
	decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
	decoded_decrypted_msg = privatekey.decrypt(decoded_encrypted_msg)
	return decoded_decrypted_msg

########## BEGIN ##########

a_message = input(">>> ")
print("Wait...")

privatekey , publickey = generate_keys()
encrypted_msg = encrypt_message(a_message , publickey)
decrypted_msg = decrypt_message(encrypted_msg, privatekey)

print ("p = ", p, "\nq = ", q)
print ("N = ", p * q)

print ((privatekey.exportKey() , len(privatekey.exportKey())))
print ("\n")

print ((publickey.exportKey() , len(publickey.exportKey())))
print ("\n")

print (" Original content: %s - (%d)",  (a_message, len(a_message)), "\n")
print ("Encrypted message: %s - (%d)",  (encrypted_msg, len(encrypted_msg)), "\n")
print ("Decrypted message: %s - (%d)",  (decrypted_msg, len(decrypted_msg)), "\n")
