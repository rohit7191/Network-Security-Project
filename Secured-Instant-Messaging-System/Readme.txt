# Aditya KS and Rohit P
Note - To run these files the machines must have pyDH and cryptography libraries installed 
##################################################################################################
To run the Server file we will need the following files

private_key1024.der
password_file.txt
CommonUtil.py
Server.py

Command to run the Server.py

python Server.py -sp <PORT> -sk <PRIVATE_KEY_FILE_PATH> -pf <PASSWORD_FILE_PATH>

example



python Server.py -sp 5050 -sk "/home/adityaks2/SecureInstantMessaging/private_key1024.der" -pf "/home/adityaks2/SecureInstantMessaging/password_file.txt"
##################################################################################################
To run the Client File we will need the following files

public_key1024.der
CommonUtil.py
Client.py

Command to run the Client.py

python Client.py -sip <SERVER_IP> -sp <SERVER_PORT> -sk <SERVER_PUBLIC_KEY_FILE_PATH>

python Client.py -sip localhost -sp 5050 -sk "C:\Python27\public_key1024.der"



Note : there is a small bug . only localhost seems to work , but the ip address does not seem to work
python Client.py -sip localhost -sp 5050 -sk "/home/adityaks2/SecureInstantMessaging/public_key1024.der"

###################################################################################################
Command To run the Password Maker File (This file must be run only if we need to modify user list or password list.The default supplied password_file should do)

open the file in an editor and specify the file_path variable value to the destination where the password file must be written to
(Apologies for not providing the destination file as a parameter)

python PasswordMaker.py


List of users and passwords pairs for testing , The last two credentials are not secure and must be used to for quick testing 

                {'Alpha': '$ABelie1',
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


