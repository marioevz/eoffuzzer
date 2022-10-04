import pytest
from eof import compile_from_dict

compile_tests = [
    # EOF V1 - Valid
    ## Yul 1
    {
        "input": {
            "version": 1,
            "sections": [
                {
                    "code": """
                    :yul
                    {
                        sstore(0, call(100000, 0xe94f5374fce5edbc8e2a8697c15331677e6ebf0b, 0, 0, 0, 0, 0))
                        sstore(1, 1)
                        stop()
                    }
                    """
                }
            ]
        },
        "expected-output": "0xEF000101002D006000600060006000600073e94f5374fce5edbc8e2a8697c15331677e6ebf0b620186a0f1600055600160015500"
    },
    ## Yul 2
    {
        "input": {
            "version": 1,
            "sections": [
                {
                    "code": """
                    :yul
                    {
                        sstore(0, callcode(100000, 0xe94f5374fce5edbc8e2a8697c15331677e6ebf0b, 0, 0, 0, 0, 0))
                        sstore(1, 1)
                        stop()
                    }
                    """
                }
            ]
        },
        "expected-output": "0xEF000101002D006000600060006000600073e94f5374fce5edbc8e2a8697c15331677e6ebf0b620186a0f2600055600160015500"
    },
    ## LLL
    {
        "input": {
            "version": 1,
            "sections": [
                {
                    "code": """
                    {
                        ; Can also add lll style comments here
                        [[0]] (ADD 1 1) 
                    }
                    """
                }
            ]
        },
        "expected-output": "0xEF000101000900600160010160005500"
    },
    ## Code + Data sections
    {
        "input": {
            "version": 1,
            "sections": [
                {
                    "code": """
                    :yul
                    {
                        sstore(0, callcode(100000, 0xe94f5374fce5edbc8e2a8697c15331677e6ebf0b, 0, 0, 0, 0, 0))
                        sstore(1, 1)
                        stop()
                    }
                    """
                },
                {
                    "data": """
                    :yul
                    {
                        sstore(0, callcode(100000, 0xe94f5374fce5edbc8e2a8697c15331677e6ebf0b, 0, 0, 0, 0, 0))
                        sstore(1, 1)
                        stop()
                    }
                    """
                },
            ]
        },
        "expected-output": "0xEF000101002D02002D006000600060006000600073e94f5374fce5edbc8e2a8697c15331677e6ebf0b620186a0f26000556001600155006000600060006000600073e94f5374fce5edbc8e2a8697c15331677e6ebf0b620186a0f2600055600160015500"
    },
    # EOF V1 - Invalid
    ## Mock EOF version
    {
        "input": {
            "version": 1,
            "mock-version": 143,
            "sections": [
                {
                    "code": """
                    :yul
                    {
                        sstore(0, callcode(100000, 0xe94f5374fce5edbc8e2a8697c15331677e6ebf0b, 0, 0, 0, 0, 0))
                        sstore(1, 1)
                        stop()
                    }
                    """
                }
            ]
        },
        "expected-output": "0xEF008F01002D006000600060006000600073e94f5374fce5edbc8e2a8697c15331677e6ebf0b620186a0f2600055600160015500"
    },
    ## Mock EOF magic
    {
        "input": {
            "version": 1,
            "mock-magic": 143,
            "sections": [
                {
                    "code": """
                    :yul
                    {
                        sstore(0, callcode(100000, 0xe94f5374fce5edbc8e2a8697c15331677e6ebf0b, 0, 0, 0, 0, 0))
                        sstore(1, 1)
                        stop()
                    }
                    """
                }
            ]
        },
        "expected-output": "0xEF8F0101002D006000600060006000600073e94f5374fce5edbc8e2a8697c15331677e6ebf0b620186a0f2600055600160015500"
    },
    ## Mock EOF Section kind
    {
        "input": {
            "version": 1,
            "sections": [
                {
                    "code": """
                    :yul
                    {
                        sstore(0, callcode(100000, 0xe94f5374fce5edbc8e2a8697c15331677e6ebf0b, 0, 0, 0, 0, 0))
                        sstore(1, 1)
                        stop()
                    }
                    """,
                    "mock-kind": 143,
                }
            ]
        },
        "expected-output": "0xEF00018F002D006000600060006000600073e94f5374fce5edbc8e2a8697c15331677e6ebf0b620186a0f2600055600160015500"
    },
    ## Mock EOF Section size
    {
        "input": {
            "version": 1,
            "sections": [
                {
                    "code": """
                    :yul
                    {
                        sstore(0, callcode(100000, 0xe94f5374fce5edbc8e2a8697c15331677e6ebf0b, 0, 0, 0, 0, 0))
                        sstore(1, 1)
                        stop()
                    }
                    """,
                    "mock-size": 0,
                }
            ]
        },
        "expected-output": "0xEF0001010000006000600060006000600073e94f5374fce5edbc8e2a8697c15331677e6ebf0b620186a0f2600055600160015500"
    },
    ## No code section
    {
        "input": {
            "version": 1,
            "sections": [
                {
                    "data": """
                    :yul
                    {
                        sstore(0, callcode(100000, 0xe94f5374fce5edbc8e2a8697c15331677e6ebf0b, 0, 0, 0, 0, 0))
                        sstore(1, 1)
                        stop()
                    }
                    """
                }
            ]
        },
        "expected-output": "0xEF000102002D006000600060006000600073e94f5374fce5edbc8e2a8697c15331677e6ebf0b620186a0f2600055600160015500"
    },
]


def test_compile_v1():
    for compile_test in compile_tests:
        assert "input" in compile_test
        assert "expected-output" in compile_test

        result = compile_from_dict(compile_test["input"])
        print(result.build().hex())
        assert result.build() == bytearray.fromhex(compile_test["expected-output"][2:])