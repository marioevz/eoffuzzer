from eof.v1 import Container
from collections.abc import Callable
import yaml

sender_sk = "45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"
sender_address = "a94f5374fce5edbc8e2a8697c15331677e6ebf0b"
sender_contract_create = "ec0e71ad0a90ffe1909d27dac207f7680abba42d" # nonce == 1

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
        "nonce": '1',
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
                sender_contract_create: {}
            },
        }
    

    
def generate_filler(container: Container, initcodegen: Callable[..., bytearray]) -> str:
    # Generate the init code
    code = container.build()
    initcode = initcodegen(code)
    tx = init_transaction_template.copy()
    tx["data"].append(":raw 0x" + initcode.hex())
    contract_result = dict()
    if container.valid:
        contract_result["code"] = "0x" + code.hex()
        contract_result["nonce"] = "1"
        contract_result["storage"] = dict()
    else:
        contract_result["shouldnotexist"] = 1
    expect = expect_preset.copy()
    expect["result"][sender_contract_create] = contract_result
    

    filler = dict()
    filler_name = container.name
    filler[filler_name] = dict()
    filler[filler_name]["_info"] = {
        "comment": "Generated using eoffuzzer, seed {}:\n{}".format(container.seed, container.description)
    }
    filler[filler_name]["env"] = default_env.copy()
    filler[filler_name]["pre"] = default_pre.copy()
    filler[filler_name]["transaction"] = tx
    filler[filler_name]["expect"] = [expect]

    output_file_name = "{}Filler.yml".format(filler_name)

    with open(output_file_name, 'w') as f:
        yaml.dump(filler, f)

    return filler_name
