import pickle
import random

import sys


from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import hashes

#process the input arguments
# parser = argparse.ArgumentParser()
# parser.add_argument("-fp", help="Destination File Path")
# args = parser.parse_args()
# if not args.fp:
#     print "Usage - python PasswordMaker.py -fp <DESTINATION_FILE_PATH>"
#     sys.exit()


class HashAndSalt:
    def __init__(self):
        self.computed_hash = 0
        self.salt = 0

    def set_computed_hash(self,computed_hash):
        self.computed_hash = computed_hash

    def set_salt(self,salt):
        self.salt = salt

user_dict = {'Alpha': HashAndSalt(),'Beta':HashAndSalt(),'Gamma':HashAndSalt(),'Delta':HashAndSalt(),'Aditya': HashAndSalt(),
             'Rohit': HashAndSalt(),'One' : HashAndSalt(),'Two': HashAndSalt(),'Three' : HashAndSalt(),'A' : HashAndSalt(),
             'B': HashAndSalt()}

file_path = "C:\Users\ADITYA\PycharmProjects\SecureInstantMessaging\password_file.txt"
#file_path = args.fp
password_dict = {'Alpha': '$ABelie1',
                 'Beta':'$ABelim11',
                 'Gamma': '$BAekjw33',
                 'Delta': '@ABikX44',
                 'Aditya': '&ejk(556',
                 'Rohit': '158$jR0R',
                 'One': 'azyXX$12',
                 'Two': 'nqT486&',
                 'Three': 'adK355$1',
                 'A' :'abc123',
                 'B': 'abc123'}

for user in password_dict:
    password = password_dict[user]
    salt = random.randint(1, 5000)
    password_and_salt = password + str(salt)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password_and_salt)
    hash = digest.finalize()
    hash_and_salt = user_dict[user]
    hash_and_salt.set_computed_hash(hash)
    hash_and_salt.set_salt(salt)
    user_dict[user] = hash_and_salt


with open (file_path ,'wb+') as f :
		pickle.dump(user_dict,f)


# def encrypt_with_shared_key(key,message,nonce):
#     cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
#     encryptor = cipher.encryptor()
#     cipher_text = encryptor.update(message) + encryptor.finalize()
#     return cipher_text
#
# d1 = pyDH.DiffieHellman()
# d2 = pyDH.DiffieHellman()
# d1_pubkey = d1.gen_public_key()
# d2_pubkey = d2.gen_public_key()
#
# shared_key = d1.gen_shared_key(d1_pubkey)
# #
# decode_key = base64.b64decode(shared_key)
# # print decode_key
# # print len(decode_key)
# #
# aes_key = decode_key[0:16]
# # print aes_key
# # print len(aes_key)
# #
# nonce = os.urandom(16)
# # print nonce
# # print len(nonce)
#
# message = "Hi How are you"
# cipher_text = encrypt_with_shared_key(aes_key,message,nonce)
# print cipher_text