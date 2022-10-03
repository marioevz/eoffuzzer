from eof import Container
from collections.abc import Callable
import yaml
import rlp
from web3 import Web3

w3 = Web3()

sender_sk = "45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"
sender_address = "a94f5374fce5edbc8e2a8697c15331677e6ebf0b"
sender_nonce = 1

create_address =  "cccccccccccccccccccccccccccccccccccccccc"
create_address_nonce = 1

create2_address = "dddddddddddddddddddddddddddddddddddddddd"
create2_address_nonce = 1

default_env = {
    "currentCoinbase": "2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
    "currentDifficulty": "0x20000",
    "currentGasLimit": "0xFF112233445566",
    "currentNumber": 1,
    "currentTimestamp": 1000,
    "previousHash": "5e20a0453cecd065ea59c37ac63e079ee08998b6045136a8ce6635c7912ec0b6",
}

default_pre = {
    sender_address: {
        "balance": '1000000000000000000',
        "code": '0x',
        "nonce": str(sender_nonce),
        "storage": {},
    },
    create_address: {
        "balance": '0',
        "code": ''':yul
        {
            calldatacopy(0, 0, calldatasize())
            pop(create(0, 0, calldatasize()))
        }
        ''',
        "nonce": str(create_address_nonce),
        "storage": {},
    },
    create2_address: {
        "balance": '0',
        "code": ''':yul
        {
            calldatacopy(0, 0, calldatasize())
            pop(create2(0, 0, calldatasize(), 0))
        }
        ''',
        "nonce": str(create2_address_nonce),
        "storage": {},
    },
}

init_transaction_template = {
    "data": [],
    "gasLimit": ["40000000"],
    "gasPrice": "10",
    "nonce": "1",
    "to": "",
    "value": ["0"],
    "secretKey": sender_sk,
}

expect_preset = {
            "network": [
                "Shanghai",
            ],
            "result": {
                sender_address: {
                    "code": "0x",
                    "nonce": "2",
                    "storage": {},
                },
            },
        }
    
def get_create_address(addr: str, intnonce: int) -> str:
    if addr.startswith('0x'):
        addr = addr[2:]

    nonce = hex(intnonce)[2:]

    if (len(addr) % 2) != 0:
        addr = '0' + addr

    if (len(nonce) % 2) != 0:
        nonce = '0' + nonce
    addr = bytes.fromhex(addr)
    nonce = bytes.fromhex(nonce)

    if nonce == bytes.fromhex('00'):
        nonce = ''
    kec = w3.keccak(hexstr=rlp.encode([addr, nonce]).hex())
    return kec[12:].hex()[2:]

def get_create2_address(addr: str, salt_int: int, initcode: bytearray) -> str:
    if addr.startswith('0x'):
        addr = addr[2:]
    if (len(addr) % 2) != 0:
        addr = '0' + addr
    
    salt = hex(salt_int)[2:]
    while len(salt) < 64:
        salt = '0' + salt

    ff = bytes.fromhex('ff')
    addr = bytes.fromhex(addr)
    salt = bytes.fromhex(salt)
    init_kec = w3.keccak(hexstr=initcode.hex())
    kec = w3.keccak(hexstr=(ff + addr + salt + init_kec).hex())
    return kec[12:].hex()[2:]
    
def generate_filler(container: Container, initcodegen: Callable[..., bytearray], create_method: str='tx') -> str:
    # Generate the init code
    code = container.build()
    initcode = initcodegen(code)
    tx = init_transaction_template.copy()
    tx["data"].append(":raw 0x" + initcode.hex())
    contract_result = dict()
    if container.is_valid():
        contract_result["code"] = "0x" + code.hex()
        contract_result["nonce"] = "1"
        contract_result["storage"] = dict()
    else:
        contract_result["shouldnotexist"] = 1
    expect = expect_preset.copy()

    if create_method=='tx':
        created_contract = get_create_address(sender_address, sender_nonce)

    elif create_method=='create':
        created_contract = get_create_address(create_address, create_address_nonce)
        tx["to"] = "0x" + create_address

    elif create_method=='create2':
        created_contract = get_create2_address(create2_address, 0, initcode)
        tx["to"] = "0x" + create2_address
    else:
        raise Exception("invalid create method: {}".format(create_method))
        
    expect["result"][created_contract] = contract_result
    
    filler = dict()
    filler_name = container.get_name()
    filler[filler_name] = dict()
    filler[filler_name]["_info"] = {
        "comment": "Generated using eoffuzzer, seed {}:\n{}".format(container.get_seed(), container.get_description())
    }
    filler[filler_name]["env"] = default_env.copy()
    filler[filler_name]["pre"] = default_pre.copy()
    filler[filler_name]["transaction"] = tx
    filler[filler_name]["expect"] = [expect]

    output_file_name = "{}Filler.yml".format(filler_name)

    with open(output_file_name, 'w') as f:
        yaml.dump(filler, f)

    return filler_name
