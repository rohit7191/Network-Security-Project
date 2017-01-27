# Secure Instant Messaging Application Client
# Authors : Aditya KS , Rohit
import socket
import json
import threading
import sys
import argparse
import pickle
import os
from CommonUtil import Client_Details
from CommonUtil import getUpdatedClientDictFromCdtList
from CommonUtil import  user_name_from_address
from CommonUtil import  is_message_type_ok
from CommonUtil import  get_hmac_from_common_key
from CommonUtil import  get_hmac_from_shared_key
from CommonUtil import  verify_hmac_with_common_key
from CommonUtil import  verify_hmac_with_shared_key
from CommonUtil import  encrypt_with_shared_key
from CommonUtil import  decrypt_with_shared_key
import pyDH
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac


# process the input arguments
parser = argparse.ArgumentParser()
parser.add_argument("-sip", help="Server Ip Address")
parser.add_argument("-sp", type=int, help="Server Port Number")
#parser.add_argument("-cp", type=int, help="Server Client Number")
parser.add_argument("-sk",help = "Server Public Key")
args = parser.parse_args()
if not args.sip:
    print "Usage - python client.py -sip server-ip -sp <PORT> -sk <SERVER_PUBLIC_KEY_PATH>"
    sys.exit()

if not args.sp:
    print "Usage - python client.py -sip server-ip -sp <PORT> -sk <SERVER_PUBLIC_KEY_PATH>"
    sys.exit()

# if not args.cp:
#     print "Usage - python client.py -sip server-ip -sp <PORT> -sk <SERVER_PUBLIC_KEY_PATH>"
#     sys.exit()

if not args.sk:
    print "Usage - python client.py -sip server-ip -sp <PORT> -sk <SERVER_PUBLIC_KEY_PATH>"
    sys.exit()

PORT = args.sp
HOST = args.sip
# CLIENT_PORT = args.cp

# Read the public key file for the Server and load it into a public key variable
public_key_file_path = args.sk
try :
    with open(public_key_file_path,'rb') as f:
		s_public_key = serialization.load_der_public_key( f.read(),backend=default_backend())
except:
    print "Error while Reading the key File"
    sys.exit()

# INPUT : Asymmetric Key,Message in Byte Format
# OUTPUT : Cipher
# Method used for asymmetric encryption
def encrypt_with_asymmetric_key(key, message):
    try :
        cipher = key.encrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(),label=None))
        return cipher
    except:
        print "Error While Encrypting the file"
        sys.exit()

# def encrypt_with_shared_key(key,message,nonce):
#     decoded_key = base64.b64decode(key)
#     aes_key = decoded_key[0:16]
#     cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
#     encryptor = cipher.encryptor()
#     cipher_text = encryptor.update(message) + encryptor.finalize()
#     return cipher_text

# INPUT : 128 By Symmetric key, message in byte format and a 128 bit nonce
# OUTPUT : Cipher encrypted using AES with CTR mode
def encrypt_with_common_key(key,message,nonce):
    try :
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(message) + encryptor.finalize()
        return cipher_text
    except:
        print "Encryption Failed"
        sys.exit()

# def decrypt_with_shared_key(key,cipher_text,nonce):
#     decoded_key = base64.b64decode(key)
#     aes_key = decoded_key[0:16]
#     cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
#     decryptor = cipher.decryptor()
#     message = decryptor.update(cipher_text) + decryptor.finalize()
#     return message

# INPUT : 128 By Symmetric key, cipher  and a 128 bit nonce
# OUTPUT : Original message from decryption using AES with CTR mode
def decrypt_with_common_key(key,cipher_text,nonce):
    try :
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        message = decryptor.update(cipher_text) + decryptor.finalize()
        return message
    except:
        print "Decryption Failed"
        sys.exit()

# INPUT : Server Public key,Signature ,Original Message
# OUTPUT : Boolean - > True iff verification does not throw an exception
def verify_signature(key,signature,message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    hash = digest.finalize()
    try:
        verifier = key.verifier(signature, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        verifier.update(hash)
        verifier.verify()
        return True
    except:
        print "Signature verification failed"
        return False


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

# INPUT : Message Type,Username,message ,Socket
# OUTPUT : None
# Method takes the inputs and creates a message_dict with message type,message and username as key value pair
# and sends the message_dict unencrypted
def send_message_to_server(message_type, username, message, s):
    s_message_dict = {'message_type': message_type, 'message': message,'username':username}
    data = pickle.dumps(s_message_dict)
    s.sendto(data,(HOST,PORT))

# INPUT : Message Type,Username,message ,Socket
# OUTPUT : None
# Method takes the inputs and creates a message_dict with message type,message and username as key value pair
# and sends the message_dict encrypted
def send_encrypted_message_to_server(message_type, message, s, s_key, nonce):
    s_message_dict = {'message_type': message_type,'message': message}
    data = pickle.dumps(s_message_dict)
    encrypted_data = encrypt_with_shared_key(s_key,data,nonce)
    s.sendto(encrypted_data,(HOST,PORT))

# INPUT : Message Type , Message ,Socket,Address,HMAC
# OUTPUT : None
# Method takes the inputs and creates a message_dict with message type,message and HMAC as key value pair
# and sends the message_dict in the plain
# Iff the Message is encrypted then HMAC is the HMAC of the plain text message , if the message is not
# encrypted the hmac is defaulted to 0
def send_message_to_client(message_type, message, s, address, h_mac):
    s_message_dict = {'message_type':message_type,'message':message,'hmac':h_mac}
    data = pickle.dumps(s_message_dict)
    s.sendto(data,address)

# INPUT : Address (PORT ,IP)
# OUTPUT : True iff the message is not from the server
def is_message_not_from_server(address):
    if HOST != address[0] and PORT != address[1]:
        return True
    else:
        return False
# Comverts the input message back to original form using pickle loads
def get_original_message_from_byte(byte_message):
    return pickle.loads(byte_message)

# INPUT : Socket, USERNAME
# OUTPUT : Message from Server to authenticate,Username
# This method does the following
# 1) Waits to recieve the Cookie from the server
# 2) Once it recieves the cookie sends back the cookie to the server
# 3) Waits for Message type = AUTH_REQ_PERM from the server and returns
# This method ignores messages from other sources
def respond_to_server_cookie(s,username):
    while True:
        try:
            inputdata = s.recvfrom(65536)
            data = inputdata[0]
            address = inputdata[1]
            if is_message_not_from_server(address):
                continue
            message_dict = pickle.loads(data)
            if message_dict['message_type'] == 'COOKIE_SERVER':
                send_message_to_server('COOKIE_CLIENT', username, message_dict['message'], s)
            elif message_dict['message_type'] == 'ERROR':
                message = get_original_message_from_byte(message_dict['message'])
                if message == '1':
                    username = raw_input("Username already logged in ,enter different user\n")
                    send_message_to_server('REQ_TO_BE_AUTHENTICATED', username, "", s)
                elif message == '2':
                    username = raw_input("Username does not exist,try again \n")
                    send_message_to_server('REQ_TO_BE_AUTHENTICATED', username, "", s)
            elif message_dict['message_type'] == 'AUTH_REQ_PERM':
                if verify_signature(s_public_key,message_dict['signature'],message_dict['message']):
                    return (get_original_message_from_byte(message_dict['message']),username)
        except socket.error,msg:
            print msg

# INPUT : Socket,Username,DH_KEY_CLIENT
# OUTPUT : Servers DH_KEY
# This method waits for the server to send back the message with Message type 'DH-KEY-S"
# If it recieves a message with message type as ERROR then the user will be prompted
# to enter the password again and the password will again be encrypted and sent back to
# the server
def wait_to_be_authenticated(s,username,dh_key_client,nonce):
    while(1):
        try :
            inputdata = s.recvfrom(65536)
            data = inputdata[0]
            address = inputdata[1]
            if is_message_not_from_server(address):
                continue
            message_dict = pickle.loads(data)
            if message_dict['message_type'] == 'DH-KEY-S':

                if verify_signature(s_public_key,message_dict['signature'],message_dict['message']):
                    return get_original_message_from_byte(message_dict['message'])
                else :
                    print "server signature verification failed .something is fishy"
                    sys.exit()
            if message_dict['message_type'] == 'ERROR':
                password = raw_input("Incorrect Password Re-enter\n")
                #compute diffie-hellman key

                encrypted_password = encrypt_with_asymmetric_key(s_public_key, password)
                # d1_pub_key_encrypted = encrypt_with_public_key(s_public_key,d1_pubkey)
                password_message_dict = {'password': encrypted_password, 'DH-KEY-C': dh_key_client,'Nonce':nonce}
                send_message_to_server('PASSWORD', username, password_message_dict, s)
        except :
            print "Error while being authenticated\n"
            return "Error"

# INPUT : Socket
# OUTPUT : Socket, Username ,Session Key with Server , Nonce for Encryption
# Following is the flow of this method
# 1) Ask the user to enter username
# 2) Send a Req to be authenticated message to the server
# 3) call respond_to_server_cookie method
# 4) Ask the user to enter the password
# 5) Encrypt the password and send the clients diffie hellman key
# 6) Call wait_to_be_authenticated method
# 7) On Successfull authentication compute session key with server and return
def login(socket):
    try:
        username = raw_input("Please Enter Username\n")

        send_message_to_server('REQ_TO_BE_AUTHENTICATED', username, "", socket)
        message_from_server,username = respond_to_server_cookie(socket, username)
        # compute g Client part of  DH key and send it to server
        password = raw_input("Please Enter the password\n")
        d1 = pyDH.DiffieHellman(5)
        d1_pubkey = d1.gen_public_key()
        encrypted_password = encrypt_with_asymmetric_key(s_public_key, password)
        nonce = os.urandom(16)
        password_message_dict = {'password': encrypted_password, 'DH-KEY-C': d1_pubkey,'Nonce' :nonce}
        send_message_to_server('PASSWORD', username, password_message_dict, socket)
        server_dh_key = wait_to_be_authenticated(socket, username, d1_pubkey,nonce)

        session_key = d1.gen_shared_key(server_dh_key)

        return (socket, username, session_key,nonce)
    except:
        print "Error while logging in\n"
        return socket



def is_client_online(client_name,clientDetailsList):
    for client in clientDetailsList:
        if client.username == client_name:
            return True
    return False

# INPUT : Socket, Client_Dict,Server Session Key ,Nonce for Encryption and kill flag
# OUTPUT : None
# method to accept the message from the user and sends it to the server
# this method responds to input from the user if its in the following format
# 1) list
# 2) send USER <MESSAGE>
# 3) logout
def send_input_msg(s, client_dict, s_key, nonce,username, kill_flag):
    try:
        while (1):

            if len(kill_flag) == 1:
                sys.exit(0)

            raw_answer = raw_input("\nEnter the message :")
            answer_list = raw_answer.split(" ")
            input_length = len(answer_list)
            command = answer_list[0]
            # If the command is list then
            # send an encrypted message to the server asking to list all the online clients
            if command == 'list':
                send_encrypted_message_to_server('LIST', command, s, s_key, nonce)

            # If the command is send
            # check if the second input in the user input is a username in the client list , else ignore
            # iff the username is a valid client who is online check if the client has been authenticated
            # authenticated here implies that a session key has been established with the client in question
            # if authenticated then directly send the CONV message
            # if not then send a REQ_TO_TALK message to the client
            elif command == 'send':
                client_name = answer_list[1]

                if client_name == username:
                    continue

                if client_name in client_dict:
                    clientDetails = client_dict[client_name]
                    ts = ""
                    for string in answer_list[2: input_length]:
                        ts = ts + " " + string
                    if clientDetails.is_authenticated:
                        encrypted_message = encrypt_with_shared_key(clientDetails.key,ts,clientDetails.nonce)
                        h_mac = get_hmac_from_shared_key(clientDetails.key, ts)
                        send_message_to_client("CONV", encrypted_message, s, (clientDetails.ip, clientDetails.port),
                                               h_mac)
                    else :
                        send_message_to_client("REQ_TO_TALK", "", s, (clientDetails.ip, clientDetails.port),0)
                        clientDetails.set_next_messages_expected('NONCE')
                        # store the input message in the temp message attribute for later use (after the session key exchange)
                        clientDetails.set_temp_message(ts)
                        client_dict[client_name] = clientDetails
            # if the command is logout then send the logout message to the server
            elif command == 'logout':
                send_encrypted_message_to_server('LOGOUT',command,s,s_key,nonce)
                # remove all client related details and exit
                for client in client_dict:
                    client_dict[client] = Client_Details()

                kill_flag.append(1)
                print "Logging Out"
                sys.exit(0)
    except socket.error ,msg:
        print "Error while sending input"
        sys.exit()

# INPUT : Data (From the client), Client Dict ,Address ,Socket, Server Key, Nonce for Encryption with server
# OUTPUT :  None
def process_client_messages(data,client_dict,address,s,s_key,nonce):
    # obtain the original Message Dict sent by the client
    message_dict = pickle.loads(data)
    message_type = message_dict['message_type']
    # iff message type is Req to talk
    # iff the message is from a source which is in client dict then send back a nonce to the sender
    # set next message expected to SESSION_KEY_FROM_SERVER from the sender of this request
    if message_type == 'REQ_TO_TALK':
        #print "Recieved " + message_type + "\n"
        username = user_name_from_address(address,client_dict)
        if username is not None:
            client_details = client_dict[username]
            client_details.set_next_messages_expected('SESSION_KEY_FROM_SERVER')
            cookie = os.urandom(16)
            client_details.set_cookie(cookie)
            client_dict[username] = client_details
            send_message_to_client('NONCE', cookie, s, address,0)
        else :
            client_details = Client_Details()
            client_details.set_ip(address[0])
            client_details.set_port(address[1])
            client_details.set_next_messages_expected('SESSION_KEY_FROM_SERVER')
            client_details.set_cookie(10)
            client_dict['new_client'] = client_details
            send_message_to_client('NONCE', 10, s, address,0)

    # iff message type is NONCE
    # Check if the message is from a source recoginizable to the client
    # if the message type is an expected message from a client at the source
    # then send a MESSAGE_REQ to the server

    elif message_type == 'NONCE':
        #print "Recieved " + message_type + "\n"
        username = user_name_from_address(address,client_dict)
        if username is not None:
            client_details = client_dict[username]
            if is_message_type_ok(message_type,client_details):
                request_dict = {'CLIENT_KEY_REQUIRED_FOR':username,'NONCE': message_dict['message']}
                send_encrypted_message_to_server('MESSAGE_REQ', request_dict, s, s_key, nonce)
                #send_message("MESSAGE_REQ","",username,s)
                #client_details.set_next_messages_expected('DH-KEY-C')
                client_dict[username] = client_details

    # iff the message type is DH-KEY-C
    # iff the message type is in the expected list of messages from the source then
    # decrypt the DH-KEY of the client from the payload if the message
    # compute the diffie hellman shared key
    # Encrypt a random number and send it back to the client
    elif message_type == 'DH-KEY-C':
        #print "Recieved " + message_type + "\n"
        username = user_name_from_address(address,client_dict)
        if username is not None :
            client_details = client_dict[username]
            if is_message_type_ok(message_type,client_details):

                #decrypt_message using common key
                encrypted_sender_dh_key = message_dict['message']
                common_key = client_details.key
                common_nonce = client_details.nonce
                d1 = client_details.dh_key

                byte_dh_key = decrypt_with_common_key(common_key, encrypted_sender_dh_key, common_nonce)

                #verify the hmac for integrity check
                if not verify_hmac_with_common_key(common_key,byte_dh_key,message_dict['hmac']):
                    print "Hmac verification failed"
                    return


                # convert back to the format
                d2_pubkey = pickle.loads(byte_dh_key)

                shared_key_with_client = d1.gen_shared_key(d2_pubkey)

                shared_nonce = client_details.nonce_client

                #encrypt a random number and store it in the cookie
                random_number = os.urandom(16)
                client_details.set_cookie(random_number)

                encrypted_random_number = encrypt_with_shared_key(shared_key_with_client,random_number,shared_nonce)
                h_mac = get_hmac_from_shared_key(shared_key_with_client, random_number)
                send_message_to_client("CLIENT_CHALLENGE", encrypted_random_number, s, address, h_mac)
                client_details.set_next_messages_expected('CLIENT_RESPONSE_CHALLENGE')
                client_details.set_key(shared_key_with_client)
                client_details.set_nonce(shared_nonce)
                client_dict[username] = client_details

    # if the message type is SESSION_KEY_FROM_SERVER
    # iff the message type is expected from the client then
    # Obtain the ticket from the message and decrypt the ticket
    # Check if the nonce inside the ticket is the same as the nonce it sent
    # to the sender of this message
    # then encrypt the Diffie hellman public key and send it back to the client
    # also compute the shared diffie hellman key from the public key the sender of this
    # message sent
    elif message_type == 'SESSION_KEY_FROM_SERVER':
        #print "Recieved " + message_type + "\n"
        username = user_name_from_address(address, client_dict)
        if username is not None:
            client_details = client_dict[username]
            if is_message_type_ok(message_type,client_details):

                # decrypt the message from the message_dict
                response_dict = message_dict['message']
                encrypted_ticket = response_dict['COMMON_KEY_TICKET']
                byte_ticket = decrypt_with_shared_key(s_key,encrypted_ticket,nonce)
                ticket = get_original_message_from_byte(byte_ticket)
                common_key = ticket['common_key']
                common_nonce = ticket['common_nonce']
                client_name = ticket['key_for']
                nonce_for_verification = ticket['NONCE_FOR_VERIFICATION']

                if nonce_for_verification != client_details.cookie:
                    print "Nonce sent to Client not same as not recieved inside ticket"
                    return

                if client_name != username:
                    return

                d1 = pyDH.DiffieHellman(5)
                d1_pubkey = d1.gen_public_key()

                decoded_key = pickle.dumps(d1_pubkey)

                # encrypt the Public key of the diffie hellman exchange with common key and nonce in the ticket
                encrypted_dh_key = encrypt_with_common_key(common_key,decoded_key,common_nonce)
                h_mac = get_hmac_from_common_key(common_key, decoded_key)
                send_message_to_client("DH-KEY-C", encrypted_dh_key, s, address, h_mac)



                #decrypt the diffie hellman key sent by the client using the common key in the ticket
                encrypted_sender_dh_key = response_dict['DH-KEY-C']
                byte_dh_key = decrypt_with_common_key(common_key,encrypted_sender_dh_key,common_nonce)

                #convert back to the format
                d2_pubkey = pickle.loads(byte_dh_key)

                shared_key_with_client = d1.gen_shared_key(d2_pubkey)


                shared_nonce = response_dict['NONCE']

                client_details.set_next_messages_expected("CLIENT_CHALLENGE")
                client_details.set_key(shared_key_with_client)
                client_details.set_nonce(shared_nonce)
                client_dict[username] = client_details

    # if the message type is CLIENT_CHALLENGE
    # iff it is in the list of expected messages for the sender of this message
    # then decrypt the challenge ,verify the hmac
    # encrypt the incoming challenge number and  new number and send it back to the sender of this message
    # also store the new number so that it can be used to verify when the sends back the challenge
    elif message_type == 'CLIENT_CHALLENGE':
        #print "Recieved " + message_type + "\n"
        username = user_name_from_address(address, client_dict)
        if username is not None:
            client_details = client_dict[username]
            if is_message_type_ok(message_type, client_details):

                key = client_details.key
                nonce = client_details.nonce
                decrypted_challenge = decrypt_with_shared_key(key,message_dict['message'],nonce)

                # verify the hmac
                if not verify_hmac_with_shared_key(key,decrypted_challenge,message_dict['hmac']):
                    print "Hmac verification failed while decrypting the challenge"
                    return


                #generate random number
                random_number = os.urandom(16)
                client_details.set_cookie(random_number)

                response_dict = {'CHALLENGE': random_number,"RESPONSE": decrypted_challenge}
                byte_data = pickle.dumps(response_dict)

                encrypted_data = encrypt_with_shared_key(key,byte_data,nonce)
                h_mac = get_hmac_from_shared_key(key, byte_data)
                send_message_to_client("CLIENT_RESPONSE_CHALLENGE", encrypted_data, s, address, h_mac)
                client_details.set_next_messages_expected("CLIENT_RESPONSE")
                client_dict[username] = client_details

    # if the message type is CLIENT_RESPONSE_CHALLENGE
    # iff it is in the list of expected messages for the sender of this message
    # then decrypt the message ,verify the hmac
    # Verify that the incoming message has the challenge which this client had sent to the sender

    # Create a new dictionary with the recieved challenge from the sender of this message and also the
    # original message stored in the temp message
    # encrypt this dictinary with the shared key and send it back
    elif message_type == 'CLIENT_RESPONSE_CHALLENGE':
        #print "Recieved " + message_type + "\n"
        username = user_name_from_address(address,client_dict)
        if username is not None:
            client_details = client_dict[username]
            if is_message_type_ok(message_type,client_details):
                key = client_details.key
                nonce = client_details.nonce

                byte_challage_response_dict = decrypt_with_shared_key(key,message_dict['message'],nonce)

                if not verify_hmac_with_shared_key(key,byte_challage_response_dict,message_dict['hmac']):
                    print "Hmac vertification failed while recieving Client Response Challege"
                    return

                challenge_response_dict = get_original_message_from_byte(byte_challage_response_dict)
                if (client_details.cookie != challenge_response_dict['RESPONSE']):
                    print "Response not correct"
                    return

                #new challenge response dict - send back the challenge and the message originally sent
                new_challeng_response_dict = {'CHALLENGE_RESPONSE': challenge_response_dict['CHALLENGE'],'CONV' : client_details.temp_message}
                byte_new_challenge_response_dict = pickle.dumps(new_challeng_response_dict)
                encrypted_new_challenge_response_dict = encrypt_with_shared_key(key,byte_new_challenge_response_dict,nonce)
                h_mac = get_hmac_from_shared_key(key,byte_new_challenge_response_dict)
                send_message_to_client("CLIENT_RESPONSE", encrypted_new_challenge_response_dict, s, address, h_mac)

                client_details.set_next_messages_expected("CONV")
                client_details.set_temp_message('')
                client_details.set_is_authenticated(True)
                #print "Setting authenticated to true"
                client_dict[username] = client_details
    # if the message type is CLIENT_RESPONSE
    # iff it is in the expected message type for the sender of this message then
    # decrypt the message
    # verify the hmac
    # Check that the message contains the challenge number which this client had sent to the server
    # Also display the CONV message on the screen
    elif message_type == 'CLIENT_RESPONSE':
        #print "Recieved " + message_type + "\n"
        username = user_name_from_address(address,client_dict)
        if username is not None:
            client_details = client_dict[username]
            if is_message_type_ok(message_type,client_details):

                key = client_details.key
                nonce = client_details.nonce

                decrypted_response = decrypt_with_shared_key(key,message_dict['message'],nonce)
                if not verify_hmac_with_shared_key(key,decrypted_response,message_dict['hmac']):
                    print "Hmac verification failed when recieving client resonse"
                    return

                challenge_response_dict = get_original_message_from_byte(decrypted_response)

                if(challenge_response_dict['CHALLENGE_RESPONSE'] != client_details.cookie):
                    print "Challenge Verification Failed"
                    return

                client_details.set_next_messages_expected("CONV")
                client_details.set_is_authenticated(True)
                #print "Setting authenticated to true"

                print "Message From " + username + " : " + challenge_response_dict['CONV']

                client_dict[username] = client_details

    # iff the message type is CONV then
    # iff it is in the expected list of messages
    # Decrypt the message and verify the hmac
    # Print the message on the screen
    elif message_type == 'CONV':
        #print "Recieved " + message_type + "\n"
        username = user_name_from_address(address, client_dict)
        clientDetails = client_dict[username]
        if not is_message_type_ok(message_type, clientDetails):
            return
        decrypted_message = decrypt_with_shared_key(clientDetails.key,message_dict['message'],clientDetails.nonce)

        if not verify_hmac_with_shared_key(clientDetails.key,decrypted_message,message_dict['hmac']):
            print "Hmac vertification failed for the message recieved"
            return
        print  "Message From : " + username +  ' : ' + decrypted_message + '\n'


def process_server_messages(data,client_dict,s,s_key,nonce):
    #data_decrypted = decrypt_with_shared_key(s_key,data,nonce
    message_dict = pickle.loads(data)
    message_type = message_dict['message_type']
    #print message_type
    if message_type == 'LOGOUT_NOTIFICATION':
        print "Recieved log out notificiation"
        logged_out_client_name = decrypt_with_shared_key(s_key,message_dict['message'],nonce)

        print logged_out_client_name + " has logged out"
        if logged_out_client_name in client_dict:
            del client_dict[logged_out_client_name]

        print "Current Online Client List \n"
        for client in client_dict:
            print client + " "

    if message_type == 'NEW_CLIENT_NOTIFICATION':

        byte_clientList = decrypt_with_shared_key(s_key, message_dict['message'], nonce)
        clientList = get_original_message_from_byte(byte_clientList)
        clientDetails = clientList[0]
        print "A new client " + clientDetails.username + " is online"
        # this method ensures only new clients in the clientList are added to the client dict
        getUpdatedClientDictFromCdtList(clientList, client_dict)


    # if the message type is list answer then decrypt the server message and update the client_dict with the new list
    if message_type == 'LIST_ANSWER':
        byte_clientList = decrypt_with_shared_key(s_key,message_dict['message'],nonce)
        clientList = get_original_message_from_byte(byte_clientList)
        # this method ensures only new clients in the clientList are added to the client dict
        getUpdatedClientDictFromCdtList(clientList,client_dict)

        print "Current Online Client List \n"
        for client in client_dict:
            print client + " "

        if len(client_dict) == 1:
            print "no other client online"

    # if message type is SESSION_KEY_FROM_SERVER
    # decrypt the common key response from the input message using the shared key with the server
    # compute the diffie hellman public key and encrypt using the common key
    # send the ticket and the encrypted diffie hellman key to the client
    elif message_type == 'SESSION_KEY_FROM_SERVER':
        response_dict = message_dict['message']
        encrypted_response_for_client_requesting = response_dict['COMMON_KEY_RESPONSE']
        byte_response_for_client_requesting = decrypt_with_shared_key(s_key,encrypted_response_for_client_requesting,nonce)
        response_for_client_requesting = get_original_message_from_byte(byte_response_for_client_requesting)
        common_key = response_for_client_requesting['common_key']
        client_name = response_for_client_requesting['key_for']
        common_nonce = response_for_client_requesting['common_nonce']

        if client_name not in client_dict:
            return

        client_details = client_dict[client_name]
        client_details.set_key(common_key)
        client_details.set_nonce(common_nonce)
        client_details.set_next_messages_expected('DH-KEY-C')
        client_port = client_details.port
        client_ip = client_details.ip


        d1 = pyDH.DiffieHellman(5)
        d1_pub_key = d1.gen_public_key()

        byte_key = pickle.dumps(d1_pub_key)
        encrypted_dh_key = encrypt_with_common_key(common_key, byte_key, common_nonce)
        nonce = os.urandom(16)
        new_response_dict={'COMMON_KEY_TICKET':response_dict['COMMON_KEY_TICKET'],'DH-KEY-C':encrypted_dh_key,'NONCE':nonce}

        client_details.set_dh_key(d1)
        client_details.set_nonce_client(nonce)
        client_dict[client_name] = client_details
        h_mac_for_encrypted_key = get_hmac_from_common_key(common_key,byte_key)
        send_message_to_client('SESSION_KEY_FROM_SERVER', new_response_dict, s, (client_ip, client_port),
                               h_mac_for_encrypted_key)


# Method which listens to messages and calls either process_client_messages or
# process_server_messages
def recieve_msgs(s, client_dict,s_key,nonce,kill_flag):
    while (1):
        try:
            #print  len(kill_flag)
            # if len(kill_flag) == 1:
            #     print "Exiting Thread"
            #     sys.exit(0)

            d = s.recvfrom(65536)
            data = d[0]
            address = d[1]

            # check if the message is from server
            if is_message_not_from_server(address):
                process_client_messages(data,client_dict,address,s,s_key,nonce)
            else:
                process_server_messages(data, client_dict,s,s_key,nonce)
        except socket.error,msg:
            print  msg


# subclass of the threading.Thread class
class myThread(threading.Thread):
    def __init__(self, threadID, sock, hostname, port, flag,username,client_dict,s_key,nonce,kill_flag):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.sock = sock
        self.hostname = hostname
        self.port = port
        self.flag = flag
        self.username = username
        self.client_dict = client_dict
        self.s_key = s_key
        self.nonce = nonce
        self.kill_flag = kill_flag

    def run(self):
        send_recieve(self.sock, self.flag, self.client_dict, self.s_key, self.nonce,self.username, self.kill_flag)


# method which calls the sending /receiving methods defined above based on a flag
def send_recieve(sock, flag, client_dict, s_key, nonce,username, kill_flag):
    if flag == 'send':
        send_input_msg(sock, client_dict, s_key, nonce,username, kill_flag)
    else:
        recieve_msgs(sock, client_dict,s_key,nonce,kill_flag)


def bind_socket(s, port):
    try:
        s.bind(('', port))
        return s
    except socket.error:
        print "Error while binding the socket to port . Check Port number"
        sys.exit()


def main():

    try :
        client_dict = {}
        kill_flag = []
        socket = create_socket()
        # socket = bind_socket(socket, CLIENT_PORT)
        # s = greet_server(s)
        socket,username,session_key,nonce = login(socket)

        print "Successfully logged in , type list to know all the online clients"

        # Create new threads
        sendThread = myThread(1, socket, HOST, PORT, "send",username,client_dict,session_key,nonce,kill_flag)
        receiveThread = myThread(2, socket, HOST, PORT, "receive",username,client_dict,session_key,nonce,kill_flag)

        # Start new Threads
        sendThread.start()
        receiveThread.start()
    except :
        print "Error occured"


if __name__ == "__main__":
    main()
