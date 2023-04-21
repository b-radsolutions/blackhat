import random
import threading
import socket
import utils.rsa as rsa
from utils.rsa import decrypt as rsa_decrypt
from utils.rc5 import decrypt
from utils.sha import hash
from models.bitset import bitset
from models.packet import Operation, IdTypes, unwrap_encrypted_operation, ProtectedOperation, ProtectedOperationIds, \
    BoolStrings, construct_encrypted_operation
import json
from utils.pallier import create_config, decrypt as p_decrypt, encrypt as p_encrypt

from utils import prime_handler


class server:
    def __init__(self):
        print('Initializing Server')
        self.host = 'localhost'
        self.port = 8000  # initiate port no. above 1024
        self.server_socket = socket.socket()  # get instance
        self.server_socket.bind((self.host, self.port))  # bind host address and port together
        self.rsa_keys = rsa.keys()  # Auto Generate RSA Keys for Key Sharing
        self.certificate = self.generate_certificate()  # Certificate Generation
        self.received_nonces = set()
        self.server_nonces = {}  # client_id -> nonce
        self.client_credentials = {}
        self.client_nonces = {}  # cle
        self.keys = {}  # client_id to keys
        self.user_keys = {} # usernames to public key in form (N, e)
        self.challenges = {}
        self.values = {}  # username to bank values
        self.user_values = {} # persistent values
        self.client_users = {}
        self.message_nonces = set()
        self.freeze = set()
        self.active_users = set()
        print('Finished Server Initialization')

    def response(self, operation: Operation, client_id: str):
        id, data = operation.id, operation.data
        if id == IdTypes.HELLO:
            return self.server_hello(data, client_id) + "|" + self.certificate
        elif id == IdTypes.KEYGEN:
            y1, y2 = data.split(":")
            self.premastersecret = rsa.decrypt(self.rsa_keys[4], self.rsa_keys[0], (int(y1), int(y2)))
            self.generate_session_key(client_id)
            # get the n and
            (p, q, _, g, _) = self.keys[client_id]['pallier']
            resp = str(p * q) + '|' + str(g)
            return resp
        elif id == IdTypes.ENCRYPTED:
            if client_id in self.client_users and self.client_users[client_id] in self.freeze:
                return "exit"
            keys = self.keys[client_id]
            (p, q, u, g, c) = self.keys[client_id]['pallier']
            # check if we have public keys for the client
            pub_keys = None
            if client_id in self.client_users and self.client_users[client_id] in self.user_keys:
                pub_keys = self.user_keys[self.client_users[client_id]]
            protected_op:ProtectedOperation = unwrap_encrypted_operation(operation, keys['hmac'], keys['rc5'], client_keys=pub_keys, server=True)
            if not protected_op:
                # do nothing
                return None
            if protected_op.nonce in self.message_nonces:
                # do nothing if nonce already seen
                return None
            else:
                self.message_nonces.add(protected_op.nonce)
            match protected_op.id:
                case ProtectedOperationIds.DEPOSIT:
                    self.values[client_id] = (self.values[client_id]*int(protected_op.data))%((p*q)**2)
                    return None
                case ProtectedOperationIds.WITHDRAW:
                    self.values[client_id] = (self.values[client_id]*int(protected_op.data))%((p*q)**2)
                    return None
                case ProtectedOperationIds.CHECK:
                     return construct_encrypted_operation(ProtectedOperationIds.CHECK, keys['rc5'], keys['hmac'], str(p_decrypt(self.values[client_id], u, p, q)))
                case ProtectedOperationIds.VERIFY:
                    # get the user and password from verification
                    string = decrypt(bitset.from_number(keys['rc5']), protected_op.data)
                    user, password = string.split('/')
                    data = None
                    if user in self.client_credentials:
                        data =  BoolStrings.TRUE if self.client_credentials[user]==password and not user in self.active_users and not user in self.freeze else BoolStrings.FALSE
                        if data==BoolStrings.TRUE:
                            self.values[client_id]=p_encrypt(p*q, g, self.user_values[user])
                            self.client_users[client_id]=user
                            self.active_users.add(user)
                            # get stored public key
                            (N, e) = self.user_keys[user]
                            self.challenges[user] = random.randint(1, N)
                        else:
                            self.challenges[user] = None
                    else:
                        self.client_credentials[user]=password
                        data = BoolStrings.TRUE
                        self.challenges[user]=None
                        self.client_users[client_id]=user
                        self.active_users.add(user)
                    return construct_encrypted_operation(ProtectedOperationIds.VERIFY, keys['rc5'],keys['hmac'], json.dumps({'valid':data.value, 'value':self.challenges[user]}))
                case ProtectedOperationIds.FREEZE:
                    username = decrypt(bitset.from_number(keys['rc5']), protected_op.data)
                    self.freeze.add(username)
                    return "exit"
                case ProtectedOperationIds.CHALLENGE:
                    # use our stored public key to undo the rsa
                    data = json.loads(protected_op.data)
                    expected = self.challenges[self.client_users[client_id]]
                    valid = BoolStrings.FALSE.value
                    if expected:
                        # check to make sure that we have data[value]
                        if 'value' in data:
                            N, e = self.user_keys[self.client_users[client_id]]
                            actual_value = rsa_decrypt(e, N, data['value'])
                            valid = BoolStrings.TRUE.value if actual_value==expected else BoolStrings.FALSE.value
                    else:
                        if 'keys' in data:
                            self.user_keys[self.client_users[client_id]]=data['keys']
                            valid = BoolStrings.TRUE.value
                    return construct_encrypted_operation(ProtectedOperationIds.VERIFY, keys['rc5'], keys['hmac'], valid)

    def save_user_value(self, client_id):
        if client_id in self.client_users:
            (p, q, u, g, c) = self.keys[client_id]['pallier']
            self.user_values[self.client_users[client_id]]=p_decrypt(self.values[client_id], u, p, q)
            self.active_users.remove(self.client_users[client_id])


    def __socket__handler(self, conn, client_id):
        while True:
            data = conn.recv(4096).decode()
            if data == "exit":
                self.save_user_value(client_id)
                break
            if data:
                message = self.response(Operation.parse_obj(json.loads(data)), client_id)
                if message=="exit":
                    conn.close()
                    break
                if message:
                    conn.send(message.encode())

    def listen(self):
        print('Listening for messages')
        # configure how many client the server can listen simultaneously
        self.server_socket.listen(2)

        while True:
            conn, address = self.server_socket.accept()
            client_id = address[0] + '::' + str(address[1])
            threading.Thread(target=self.__socket__handler, args=(conn, client_id,), daemon=True).start()

    def server_hello(self, data, client_id):
        # "Chooses information from the selected version provided by the client"
        # In this specific version, no selection occured but the step was still incorporated for completeness
        self.server_version, self.client_nonces[
            client_id], self.sessionID, self.cipherSuite, self.compression = data.split(
            "|")
        # Data -> Version of SSL, A Random Nonce, Session ID for Communication, Cipher information, Compression type
        self.cipherAlgorithm, self.MACAlgorithm, self.cipherType, self.isExportable, self.hashSize = self.cipherSuite.split(
            ":")
        self.server_nonces[client_id] = next(prime_handler.new())
        message = [self.server_version, str(self.server_nonces[client_id]), self.sessionID, self.cipherSuite,
                   self.compression]
        return "|".join(message)

    def generate_certificate(self):
        return "Certficate:" + str(self.rsa_keys[0]) + ":" + str(self.rsa_keys[3])

    def generate_session_key(self, client_id):
        print('Setting up connection')
        serverNonce = bitset.from_number(self.server_nonces[client_id])
        premasterSecret = bitset.from_number(self.premastersecret)
        clientNonce = bitset.from_number(int(self.client_nonces[client_id]))
        if client_id in self.client_nonces:
            session_key = hash(premasterSecret.__repr__() + serverNonce.__repr__() + clientNonce.__repr__())
            session_key = session_key << (8 - len(format(session_key, 'b')) % 8)
            self.keys[client_id] = {'rc5': session_key, 'hmac': session_key,
                                    'pallier': create_config()}
            self.values[client_id] = self.keys[client_id]['pallier'][4] # initial c value

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.server_socket.close()

