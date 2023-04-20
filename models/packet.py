import json
from random import randint

from pydantic import BaseModel, root_validator, ValidationError
from enum import Enum
from typing import Optional

from utils.hmac import ValidateHMAC, GenerateHMAC
from models.bitset import bitset
from utils.rc5 import decrypt, encrypt
from utils.rsa import decrypt as rsa_decrypt
from utils.sha import hash

class BoolStrings(Enum):
    FALSE = "false"
    TRUE = "true"


class ProtectedOperationIds(Enum):
    DEPOSIT = 0
    WITHDRAW = 1
    CHECK = 2
    VERIFY = 3
    FREEZE = 4
    CHALLENGE = 5


class ProtectedOperation(BaseModel):
    id: ProtectedOperationIds
    nonce: int
    data: Optional[str]  # binary encoded string
    value: Optional[int]  # value in cents for deposit and withdraw


class IdTypes(Enum):
    HELLO = 0
    KEYGEN = 1
    ENCRYPTED = 2


class Operation(BaseModel):
    id: IdTypes
    data: str
    mac: Optional[str]  # all encrypted messages will have a mac
    signature:Optional[tuple] # this will need to be a json array

    @root_validator
    def check_mac_exists(cls, values):
        id, mac = values.get('id'), values.get('mac', None)
        if id == IdTypes.ENCRYPTED and mac is None:
            raise ValueError('No MAC presented')
        return values


def unwrap_encrypted_operation(op: Operation, hmac_key, rc5_key, client_keys = None, server=False) -> Optional[ProtectedOperation]:
    if op.id != IdTypes.ENCRYPTED:
        raise ValidationError('Invalid Operation Type supplied to unwrap')
    # validate hmac
    if not ValidateHMAC(op.data, hmac_key, op.mac):
        raise ValidationError('Inconsistency between mac and message data found')
    if op.signature and client_keys:
        # verify the signature
        N, e = client_keys
        value = rsa_decrypt(e, N, op.signature)
        if value!=(hash(op.data)>>32):
            return None

    # begin decryption
    k_bitset = bitset.from_number(rc5_key)
    # this could lead to a number of different encryption types
    string = decrypt(k_bitset, op.data, _type=str)  # this will give a json value
    p_op = ProtectedOperation.parse_obj(json.loads(string))
    if server:
        if p_op.id in (ProtectedOperationIds.CHECK, ProtectedOperationIds.DEPOSIT, ProtectedOperationIds.WITHDRAW):
            if not op.signature:
                return None
    # if we have a signature then we should check if decrypting shows equivalence
    return p_op


def construct_encrypted_operation(p_op_id: ProtectedOperationIds, rc5_key, hmac_key, data):
    encrypted_data = encrypt(bitset.from_number(rc5_key), ProtectedOperation.parse_obj(
        {'id': p_op_id, 'nonce': randint(0, 2**128),'data': data}
    ).json())
    return Operation.parse_obj(
        {'id': IdTypes.ENCRYPTED, 'data': encrypted_data, 'mac': GenerateHMAC(encrypted_data, hmac_key)}).json()
