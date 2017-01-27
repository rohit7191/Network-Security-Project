# Secure Instant Messaging Application Server
# Authors : Aditya KS, Rohit
import argparse
import random
import pickle
import socket
import sys
import pyDH
import os
from CommonUtil import Client_Details
from CommonUtil import ClientDetailsInTransit
from CommonUtil import getCdtListFromDict
from CommonUtil import user_name_from_address
from PasswordMaker import HashAndSalt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from CommonUtil import encrypt_with_shared_key
from CommonUtil import decrypt_with_shared_key

parser = argparse.ArgumentParser()
parser.add_argument("-sp", type=int, help="Server Port Number")
parser.add_argument("-sk",help= "Server Private Key File")
parser.add_argument("-pf",help= "Password File")
args = parser.parse_args()
if not args.sp:
    print "Usage -python server.py -sp <PORT> -sk <SERVER_PRIVATE_KEY_FILE_PATH> -pf <PASSWORD_FILE_PATH>"
    sys.exit()
if not args.sk:
    print "Usage -python server.py -sp <PORT> -sk <SERVER_PRIVATE_KEY_FILE_PATH> -pf <PASSWORD_FILE_PATH>"
    sys.exit()
if not args.pf:
    print "Usage -python server.py -sp <PORT> -sk <SERVER_PRIVATE_KEY_FILE_PATH> -pf <PASSWORD_FILE_PATH>"
    sys.exit()

PORT = args.sp

# Random number used in computing Cookies that will be sent to clients on Request for authentication
SERVER_SECRET = str(random.randint(1, 5000))

# Read the password hashes from the input password hash file
password_file_path = args.pf
try :
    with open (password_file_path,'rb') as f:
		user_dict = pickle.loads(f.read())
except:
    print "Error while reading password file"
    sys.exit(0)

# Read the private key file for the Server and load it into a private key variable
private_key_file_path = args.sk
try :
    with open(private_key_file_path,'rb') as f:
		s_private_key = serialization.load_der_private_key( f.read(),password=None,backend=default_backend())
except :
    print "Error while loading Private key file"
    sys.exit()

# INPUT : Message
# OUTPUT : Signature
# Method takes in a message in byte format and returns a signature
def sign_message(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    hash = digest.finalize()
    signer = s_private_key.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                  hashes.SHA256())
    signer.update(hash)
    signature = signer.finalize()
    return  signature

# INPUT : Asymmetric Key,Cipher
# OUTPUT : Original Message in Byte Format
# Method used for asymmetric decryption
def decrypt_message_with_asymmetric_key(key, cipher):
    try :
        return  key.decrypt(cipher,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),algorithm=hashes.SHA1(),label=None))
    except:
        print "Error while decrypting"
        sys.exit()

# method to create a UDP socket
# socket.AF_INET ==> Implies IpV4
# socket.SOCK_DGRAM ==> Implies UDP
def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return s
    except socket.error:
        print "Error while creating a socket"
        sys.exit()



# method to bind the socket to the specified server port
def bind_socket(s, port):
    try:
        s.bind(('', port))
        return s
    except socket.error:
        print "Error while binding the socket to port . Check Port number"
        sys.exit()


# INPUT : Message Type, Message, Socket object , Address
# OUTPUT : None
# 1) Creates a signature from the message
# 2) Puts the message_type,message and signature into a dictionary
# 3) Dumps the dictionary into a byte stream and sends it to the address it via socket
def send_message_with_sign(message_type, message, s, address):

    byte_message = convert_message_to_byte(message)
    signature = sign_message(byte_message)
    s_message_dict = {'message_type': message_type, 'message': byte_message,
                      'signature': signature}
    data = pickle.dumps(s_message_dict)
    s.sendto(data, address)

# INPUT : Message Type, Message, Socket object , Address
# OUTPUT : None

# 1) Puts the message_type,message into a dictionary
# 2) Dumps the dictionary into a byte stream and sends it to the address it via socket
def send_messagew_without_sign(message_type, message, s, address):

    s_message_dict = {'message_type': message_type, 'message': message,
                      'signature': 0}
    data = pickle.dumps(s_message_dict)
    s.sendto(data, address)

# INPUT : Message
# OUTPUT : Byte Stream of the input array
def convert_message_to_byte(message):
    return pickle.dumps(message)

# INPUT : Message Type and Client_Detials object
# OUTPUT : Boolean based on whether the message_type is in the next_messages_expected list
def is_message_type_ok(message_type,client_details):
    if message_type in client_details.next_messages_expected:
        return True
    else:
        return False



# INPUT : Socket, Client Dict ,Address of the sender, message sent by the sender
# OUTPUT : Updated Client Dict
# This method resonds to authenticated clients only . If the message is from any other source
# ignores it
def respond_to_authenticated_clients(s,client_dict,address,message):
    username = user_name_from_address(address,client_dict)
    if username is not None:
        # decrypt message
        client_details = client_dict[username]
        key = client_details.key
        nonce = client_details.nonce

        decrypted_message = decrypt_with_shared_key(key,message,nonce)

        message_dict = pickle.loads(decrypted_message)

        msg = message_dict['message']

        # If message_type is of 'LIST" prepare a list of Online Clients
        # Encrypt the client list and send to the sender
        if message_dict['message_type']== 'LIST':

            clientList = getCdtListFromDict(client_dict)

            byte_clientList = pickle.dumps(clientList)
            encrypted_clientList = encrypt_with_shared_key(key,byte_clientList,nonce)

            message_transit_dict = {'message_type' : 'LIST_ANSWER','message':encrypted_clientList,'hmac':0}


            data = pickle.dumps(message_transit_dict)
            #data_encrypted = encrypt_with_shared_key(key,data,nonce)
            s.sendto(data,address)
            return client_dict

        # If message type is MESSAGE_REQ
        # Compute  a common shared key and common nonce for encryption between the clients
        # Create dictionary for the client requesting the MESSAGE_REQ with common key, The username of the client which the sending client is requesting to talk to and the
        # common nonce used for encryption
        # Encrypt the above dictionary

        # Create a Dictionary for the ticket to the 2nd Client with common key,common nonce for encryption and the Nonce used for verification which it had sent to Client1
        # Encrypt the above dictionary
        # Put the above encrypted dictionaries in one more dictionary called Response Dict and treat it as message payload
        # Prepare a message transit dictionary with Message Type as SESSION_KEY_FROM_SERVER , Response Dict as  Message and send to the Requesting Client
        elif message_dict['message_type'] == 'MESSAGE_REQ':
            common_key = os.urandom(16)
            common_nonce = os.urandom(16)
            repsonse_for_client_requesting = {'common_key': common_key ,'key_for':msg['CLIENT_KEY_REQUIRED_FOR'],'common_nonce':common_nonce}
            byte_resonse_for_requested_client_dict = pickle.dumps(repsonse_for_client_requesting)
            encrypted_response_for_client_requesting = encrypt_with_shared_key(key,byte_resonse_for_requested_client_dict,nonce)

            ticket_to_requested_client = {'common_key':common_key,'key_for':username,'common_nonce':common_nonce,'NONCE_FOR_VERIFICATION':msg['NONCE']}
            if msg['CLIENT_KEY_REQUIRED_FOR'] not in client_dict:
                return client_dict

            requested_client_details = client_dict[msg['CLIENT_KEY_REQUIRED_FOR']]
            if not requested_client_details.is_authenticated:
                return client_dict
            ckey = requested_client_details.key
            cnonce = requested_client_details.nonce
            byte_ticket_to_requested_client = pickle.dumps(ticket_to_requested_client)
            encrypted_ticket_to_requested_client = encrypt_with_shared_key(ckey,byte_ticket_to_requested_client,cnonce)


            response_dict = {'COMMON_KEY_RESPONSE': encrypted_response_for_client_requesting,'COMMON_KEY_TICKET':encrypted_ticket_to_requested_client}

            message_transit_dict = {'message_type' : 'SESSION_KEY_FROM_SERVER','message': response_dict,'hmac' : 0}

            data = pickle.dumps(message_transit_dict)

            s.sendto(data, address)
            return client_dict

        # If message type is LOGOUT then
        # Re instantiate the Client Details object for the client in Client Dict
        # Send the information that this client has logged out to all the online clients
        elif message_dict['message_type']== 'LOGOUT':
            # set authenticated to false and set the key to 0
            # client_details = client_dict[username]
            # client_details.set_is_authenticated(False)
            # client_details.set_key(0)
            # client_dict[username] = client_details
            client_dict[username] = Client_Details()

            clientList = getCdtListFromDict(client_dict)
            #print len(clientList)

            for client in client_dict:
                clientDetails = client_dict[client]
                if clientDetails.is_authenticated:
                    print "sending logout message to " + client
                    encrypted_message = encrypt_with_shared_key(clientDetails.key,username,clientDetails.nonce)
                    message_transit_dict = {'message_type': 'LOGOUT_NOTIFICATION', 'message': encrypted_message,
                                            'hmac': 0}
                    data = pickle.dumps(message_transit_dict)
                    s.sendto(data,(clientDetails.ip,clientDetails.port))

            return client_dict








# INPUT : Socket, Client Dict ,Address of the sender, message sent by the sender
# OUTPUT : Updated Client Dict
# This method resonds to unauthenticated clients only . If the message is from any other source
# ignores it

def respond_to_un_authenticated_clients(s, client_dict, username, message_type, message, address):
    try:

        # if message type is 'REQ_TO_BE_AUTHENTICATED'
        # check if the username is a valid user in client_dict and not already authenticated
        # compute a cookie which is a function of username,source address and a server secret
        if message_type == 'REQ_TO_BE_AUTHENTICATED':
            if username in client_dict:
                client_details = client_dict[username]
                if not client_details.is_authenticated:

                    cookie = compute_cookie(username,address[0],address[1])
                    send_messagew_without_sign('COOKIE_SERVER',cookie,s,address)
                    return client_dict
                # if client is already authenticated from a different source send an error
                else:
                    send_message_with_sign('ERROR', '1', s, address)
                    return client_dict
            # if the username does not exist ,then send a user name does not exist method
            else:
                send_message_with_sign('ERROR', '2', s, address)
                return client_dict

        # if the message_type is 'COOKIE_CLIENT'
        # compute the cookie again for the user with username,source address and check if it matches
        # with the message from the client ,if yes then send a message to the client asking it
        # authenticate itself ,after signing it
        # also set the next messages_expected as 'PASSWORD'
        if message_type == 'COOKIE_CLIENT':

            if username in client_dict:
                if is_cookie_valid(message,username,address):
                    #print "cookie valid"
                    send_message_with_sign("AUTH_REQ_PERM", "Authenticate Urself", s, address)
                    client_details = client_dict[username]
                    client_details.set_next_messages_expected('PASSWORD')
                    client_dict[username] = client_details
                    return client_dict

        # if the message type is PASSWORD
        # check if it is an expected message for the client
        # if yes then decrypt the password which the client has sent
        # verify that the password mataches
        # compute the server's diffehellman key
        # sign the diffiehellman key and send it to the client
        # set the clientDetails object for the Client with appropriate values for
        # key,nonce for symmetric encryption ,authenticated flag to true
        if message_type == 'PASSWORD':
            if username in client_dict:
                client_details = client_dict[username]
                if message_type in client_details.next_messages_expected:
                    password_message_dict = message
                    decrypted_password = decrypt_message_with_asymmetric_key(s_private_key, password_message_dict['password'])
                    if verfiy_password(username,decrypted_password):
                        d2 = pyDH.DiffieHellman(5)
                        send_message_with_sign("DH-KEY-S", d2.gen_public_key(), s, address)

                        skc = d2.gen_shared_key(password_message_dict['DH-KEY-C'])

                        client_details.set_ip(address[0])
                        client_details.set_port(address[1])
                        client_details.set_next_messages_expected('MESSAGE_REQ')
                        client_details.set_next_messages_expected('LOGOUT')
                        client_details.set_is_authenticated(True)
                        client_details.set_key(skc)
                        client_details.set_nonce(password_message_dict['Nonce'])
                        client_details.set_next_messages_expected('LIST')
                        client_dict[username] = client_details
                        notify_all_online_clients_about_new_list(client_dict,s,client_details,username)

                        return client_dict
                    else:
                        send_message_with_sign("ERROR", "3", s, address)
                        return client_dict
    except socket.error,msg:
        print msg
        return client_dict

def notify_all_online_clients_about_new_list(client_dict,s,new_client_Details,username):
    clientList = []
    new_client_temp = ClientDetailsInTransit(username, new_client_Details.port, new_client_Details.ip)
    clientList.append(new_client_temp)

    for client in client_dict:
        clientDetails = client_dict[client]
        if clientDetails.is_authenticated and client != username:
            byte_clientList = pickle.dumps(clientList)
            shared_key = clientDetails.key
            shared_nonce = clientDetails.nonce
            encrypted_clientList = encrypt_with_shared_key(shared_key,byte_clientList,shared_nonce)
            message_transit_dict = {'message_type': 'NEW_CLIENT_NOTIFICATION', 'message': encrypted_clientList, 'hmac': 0}
            data = pickle.dumps(message_transit_dict)
            s.sendto(data,(clientDetails.ip,clientDetails.port))


# INPUT : Username , Password
# OUTPUT : Boolean Based on password being correct or not
# method to verify the password
def verfiy_password(username,password):
    hash_salt = user_dict[username]
    password_and_salt = password + str(hash_salt.salt)
    hash = compute_hash(password_and_salt)
    if hash == hash_salt.computed_hash:
        return  True
    else :
        return False

# INPUT : String(Message)
# OUTPUT : Hash of the String
def compute_hash(message):
    try:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message)
        hash = digest.finalize()
        return hash
    except:
        print "Hashing failed"
        sys.exit()

# INPUT : PORT IP CLIENT_DICT
# OUTPUT : Boolean based on whether the port ip belong to an authenticated client in client_dict
def is_message_from_authenticated_client(port,ip,client_dict):
    for username in client_dict:
        client_details = client_dict[username]
        if client_details.port == port and client_details.ip == ip and client_details.is_authenticated:
            return True
    return False


# INPUT : Username IP PORT
# OUTPUT : Hash(username|IP|PORT|SERVER_SECRET)
def compute_cookie(username,ip,port):
    cookie_content = username+str(ip)+str(port) + SERVER_SECRET
    hash = compute_hash(cookie_content)
    return  hash

# INPUT : Cookie Username Address
# OUTPUT : Boolean based on whether (cookie = Hash(username|IP|PORT|SERVER_SECRET)
def is_cookie_valid(cookie,username,address):
    if compute_cookie(username,address[0],address[1]) == cookie:
        return True
    else :
        return False


# method which handles incoming client messages and responds back appropriately
def handle_messages_from_client(s, client_dict):
    while True:
        try:
            # Read the socket buffer
            incomingMsg = s.recvfrom(65536)
            data = incomingMsg[0]
            #

            address = incomingMsg[1]
            if is_message_from_authenticated_client(address[1],address[0],client_dict) :
                client_dict = respond_to_authenticated_clients(s,client_dict,address,data)
            else :
                message_dict = pickle.loads(data)
                message_type = message_dict['message_type']
                username = message_dict['username']
                message = message_dict['message']
                client_dict = respond_to_un_authenticated_clients(s, client_dict, username, message_type, message, address)

        except :
            continue





def main():
    udp_socket = create_socket()
    udp_socket = bind_socket(udp_socket, PORT)
    print "Server Initialized  ...."

    # Initialize Client Dict with username and client details pair
    client_dict = {}
    for username in user_dict:
        client_dict[username] = Client_Details()

    handle_messages_from_client(udp_socket, client_dict)


if __name__ == "__main__":
    main()
