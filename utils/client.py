"""
Client will need to listen to input stream (could be from file)
deposit money
withdraw money
check balance

also establish authentication/ include identifying information in packet
"""
import socket
from utils.rsa import keys as rsa_keys, encrypt as rsa
from random import randint
from utils.rc5 import encrypt
from utils.hmac import GenerateHMAC
from utils.sha import hash
from models.bitset import bitset
from models.packet import Operation, ProtectedOperation, unwrap_encrypted_operation, ProtectedOperationIds, IdTypes, \
    BoolStrings
from utils import prime_handler
from utils.pallier import encrypt as p_encrypt, get_extended_factors
import json
import os


class client:
    def __init__(self):
        self.host = socket.gethostname()  # as both code is running on same pc
        self.port = 5128  # socket server port number
        self.rsa_keys = None
        self.client_socket = socket.socket()  # instantiate
        self.premasterSecret = randint(1, 2**128)
        self.sessionKey = None
        self.pallier = (0, 0, 0)  # n, g, g_inv

    def send_information(self, message):
        try:
            self.client_socket.connect((self.host, self.port))
        except:
            pass
        self.client_socket.send(message.encode())

    def receive_information(self):
        try:
            self.client_socket.connect((self.host, self.port))
        except:
            pass
        data = self.client_socket.recv(4096).decode()  # receive response
        return data

    # Client Hello
    def init(self):
        self.version = "1.3"
        self.randomClientNonce = str(next(prime_handler.new()))
        self.sessionID = str(next(prime_handler.new()))
        self.cipherSuite = ":".join(["RC5", "SHA-1", "stream", "F", "20", ])
        self.compression = "SHA-1"
        message = "|".join([self.version, self.randomClientNonce, self.sessionID, self.cipherSuite, self.compression])
        packet = Operation.parse_obj({'id': IdTypes.HELLO, 'data': message})
        self.send_information(packet.json())
        SERVER_HELLO = self.receive_information().split("|")
        self.verify_server_information(SERVER_HELLO)
        SERVER_CERTIFICATE, SERVER_RSA_N, SERVER_RSA_E = SERVER_HELLO[-1].split(":")
        self.pub_keys = {} # bind user to public key
        self.authenticate_server(SERVER_CERTIFICATE)
        self.key_exchange(SERVER_RSA_E, SERVER_RSA_N)
        n, g = self.receive_information().split('|')  # pallier public and generator
        g_inv, _ = get_extended_factors(int(g), int(n) ** 2)
        self.pallier = (int(n), int(g), g_inv)
        self.generate_session_key()

    def bind_public_private(self, value):
        # generate a public and private key
        if not value:
            # generate new keys and send them to the server
            self.rsa_keys = rsa_keys()
            N, _, _, e, _ = self.rsa_keys
            print('Your RSA keys are: ')
            print(" ".join([str(_) for _ in self.rsa_keys]))
            print('You will be prompted for this when you try to log in again so don\'t misplace them')
            print('The above format is accepted, so we recommend copying this directly')
            data={'keys':(N, e)}
        else:
            # prompt rsa values
            while True:
                rsa_string = input('Please input your RSA value space delimited in the form (N, p, q, e, d), any other form will not be accepted\n')
                if len(rsa_string.split(' '))!=5:
                    os.system('cls' if os.name == 'nt' else 'clear')
                    print('Invalid format for RSA keys submitted')
                    print('There is no way to recover your account without knowing this, please restart the server')
                    continue
                else:
                    try:
                        _ = [int(_) for _ in rsa_string.split(' ')]
                    except:
                        os.system('cls' if os.name == 'nt' else 'clear')
                        print('Invalid format for RSA keys submitted')
                        print('There is no way to recover your account without knowing this, please restart the server')
                        continue
                    N, p, q, e, d = [int(_) for _ in rsa_string.split(' ')]
                    self.rsa_keys = (N, p, q, e, d)
                    break
            N, p, q, e, d = self.rsa_keys
            encrypted_value = rsa(d, N, value)
            data = {'value':encrypted_value}
        p_op = ProtectedOperation.parse_obj(
            {'id': ProtectedOperationIds.CHALLENGE, 'data': json.dumps(data),
             'nonce': randint(0, 2 ** 128)})
        self.send_encrypted_operation(p_op)
        response_p_op = self.receive_encrypted_message()
        return response_p_op.data == BoolStrings.TRUE.value

    def verify_server_information(self, response):
        self.randomServerNonce = response[1]
        try:
            assert self.version == response[0]
            assert self.sessionID == response[2]
            assert self.cipherSuite == response[3]
            assert self.compression == response[4]
            return True
        except:
            print("Couldn't Coordinate Information with the Server")

    # Server Authenticated from Authentication Client
    def authenticate_server(self, certificate):
        if certificate == "Certificate":
            return True
        return False

    # Encrypt premaster secret and Send it to the Server
    def key_exchange(self, e, N):
        rsaPow, rsaCipher = rsa(int(e), int(N), self.premasterSecret)
        packet = Operation.parse_obj({'id': IdTypes.KEYGEN, 'data': str(rsaPow) + ":" + str(rsaCipher)})
        self.send_information(packet.json())

    def generate_session_key(self):
        serverNonce = bitset.from_number(int(self.randomServerNonce))
        premasterSecret = bitset.from_number(self.premasterSecret)
        clientNonce = bitset.from_number(int(self.randomClientNonce))
        session_key = hash(premasterSecret.__repr__() + serverNonce.__repr__() + clientNonce.__repr__())
        # align with 8 bits
        self.sessionKey = session_key << (8 - len(format(session_key, 'b')) % 8)

    def send_encrypted_operation(self, encrypted_operation: ProtectedOperation):
        # assumes we already encrypted the data
        data = encrypted_operation.json()
        encrypted_data = encrypt(bitset.from_number(self.sessionKey), data)
        mac = GenerateHMAC(encrypted_data, self.sessionKey)
        packet = Operation.parse_obj({'id': IdTypes.ENCRYPTED, 'data': encrypted_data, 'mac': mac})
        if self.rsa_keys:
            N, _, _, _, d = self.rsa_keys
            m_hash = hash(encrypted_data)>>32
            packet.signature = rsa(d, N, m_hash) # format from hex
        self.send_information(packet.json())

    def receive_encrypted_message(self):
        operation = Operation.parse_obj(json.loads(self.receive_information()))
        protected_operation = unwrap_encrypted_operation(operation, self.sessionKey, self.sessionKey)
        # we should only have a couple valid values here
        assert protected_operation.id in (ProtectedOperationIds.CHECK, ProtectedOperationIds.VERIFY, ProtectedOperationIds.CHALLENGE)
        return protected_operation

    def verify_account(self, account):
        p_op = ProtectedOperation.parse_obj(
            {'id': ProtectedOperationIds.VERIFY, 'data': encrypt(bitset.from_number(self.sessionKey), account),
             'nonce': randint(0, 2 ** 128)})
        self.send_encrypted_operation(p_op)
        response_p_op = self.receive_encrypted_message()
        # take the format (valid, value)
        data = json.loads(response_p_op.data)
        valid, value = data['valid'],data['value']
        if valid==BoolStrings.TRUE.value:
            valid = self.bind_public_private(value)
            return valid
        return False

    def freeze_account(self, username):
        p_op = ProtectedOperation.parse_obj(
            {'id': ProtectedOperationIds.FREEZE, 'data': encrypt(bitset.from_number(self.sessionKey), username),
             'nonce': randint(0, 2 ** 128)})
        self.send_encrypted_operation(p_op)

    def deposit_to_account(self, deposit):
        n, g, _ = self.pallier
        p_op = ProtectedOperation.parse_obj(
            {'id': ProtectedOperationIds.DEPOSIT, 'data': p_encrypt(n, g, deposit), 'nonce':randint(0, 2 ** 128)})
        self.send_encrypted_operation(p_op)

    def withdraw_from_account(self, withdrawal):
        n, g, g_inv = self.pallier
        p_op = ProtectedOperation.parse_obj(
            {'id': ProtectedOperationIds.WITHDRAW, 'data': p_encrypt(n, g, n - withdrawal % n),
             'nonce': randint(0, 2 ** 128)})
        self.send_encrypted_operation(p_op)

    def check_account_balance(self):
        p_op = ProtectedOperation.parse_obj(
            {'id': ProtectedOperationIds.CHECK, 'data': bitset.from_number(next(prime_handler.new())).__repr__(),
             'nonce': randint(0, 2 ** 128)})
        self.send_encrypted_operation(p_op)
        response_p_op = self.receive_encrypted_message()
        return int(response_p_op.data)

    def exit(self):
        self.send_information("exit")
        self.client_socket.close()
