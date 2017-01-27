from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64


class Client_Details:
    def __init__(self):
        self.port = 0
        self.ip = 0
        self.is_authenticated = False
        self.next_messages_expected = []
        self.cookie = 0
        self.key = 0
        self.nonce = 0
        self.dh_key = 0
        self.nonce_client = 0
        self.temp_message = ''

    def set_port(self, port):
        self.port = port

    def set_ip(self, ip):
        self.ip = ip

    def set_is_authenticated(self, val):
        self.is_authenticated = val

    def set_next_messages_expected(self, message_type):
        self.next_messages_expected.append(message_type)

    def set_cookie(self, cookie):
        self.cookie = cookie

    def set_key(self,key):
        self.key = key

    def set_nonce(self,nonce):
        self.nonce = nonce

    def set_dh_key(self,dh_key):
        self.dh_key = dh_key

    def set_nonce_client(self,nonce_client):
        self.nonce_client = nonce_client

    def set_temp_message(self,temp_message):
        self.temp_message = temp_message




class ClientDetailsInTransit:
    def __init__(self ,username,port,ip):
        self.username = username
        self.port = port
        self.ip = ip


# class ClientDetailsForCookie:
#     def __init__(self ,username,port,ip,is_verified):
#         self.username = username
#         self.port = port
#         self.ip = ip
#         self.is_verfied = is_verified
#
#     def set_is_verified(self,is_verified):
#         self.is_verfied = is_verified


# INPUT : Client Dictionary with key = username and value = Client_Details()
# OUTPUT : List of ClientDetailsTemp all the clients in this are authenticated with the server
def getCdtListFromDict(client_dict):
    clinetDetailsInTransitList = []
    for username in client_dict:
        client_details = client_dict[username]
        if client_details.is_authenticated:
            clinetDetailsInTransitList.append(ClientDetailsInTransit(username, client_details.port, client_details.ip))
    return clinetDetailsInTransitList

# INPUT : ClientDetailsInTransitList ,client_cict
# OUTPUT : None
# Updates the client_dict by adding a new key value pair from the input list if it is not already present
def getUpdatedClientDictFromCdtList(clientDetailsInTransitList,client_dict):
    for client in clientDetailsInTransitList:
        if client.username in client_dict:
            continue
        else :
            clientDetail = Client_Details()
            clientDetail.set_port(client.port)
            clientDetail.set_ip(client.ip)
            client_dict[client.username] = clientDetail

# method which returns username of a client in a particular address
def user_name_from_address(address,client_dict):
    for username in client_dict:
        client_details = client_dict[username]
        if client_details.port == address[1] and client_details.ip == address[0]:
            return username
    return None

# method which returns True if the message type is in the expected list
def is_message_type_ok(message_type,client_details):
    if message_type in client_details.next_messages_expected:
        return True
    else:
        return False

# encrypt with shared key
# decodes the input key to base 64 and obtains the first 128 bits and encrypts the input message with AES and CTR mode
def encrypt_with_shared_key(key,message,nonce):
    decoded_key = base64.b64decode(key)
    aes_key = decoded_key[0:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(message) + encryptor.finalize()
    return cipher_text

# Same as above method but decrypts
def decrypt_with_shared_key(key,cipher_text,nonce):
    decoded_key = base64.b64decode(key)
    aes_key = decoded_key[0:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    message = decryptor.update(cipher_text) + decryptor.finalize()
    return message

# returns hmac for a given msg using the key to compute
def get_hmac_from_common_key(key, msg):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(msg)
    h_mac = h.finalize()
    return h_mac
# transforms the key to a 128 bit key and computes hmac and returns the hmac
def get_hmac_from_shared_key(key,msg):
    decoded_key = base64.b64decode(key)
    hmac_key = decoded_key[0:16]
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(msg)
    h_mac = h.finalize()
    return h_mac

def verify_hmac_with_common_key(key,msg,h_mac):
    try :
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(msg)
        h.verify(h_mac)
        return True
    except:
        return False

def verify_hmac_with_shared_key(key,msg,h_mac):
    try :
        decoded_key = base64.b64decode(key)
        hmac_key = decoded_key[0:16]
        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(msg)
        h.verify(h_mac)
        return True
    except:
        return False

