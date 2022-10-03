import sys
def compile(s: str) -> bytearray:
    YUL_PREFIX = ":yul"
    RAW_PREFIX = ":raw"
    SOLIDITY_PREFIX = ":solidity"
    ABI_PREFIX = ":abi"
    if s.startswith(YUL_PREFIX):
        from compilers.yul import compile_yul
        return compile_yul(s[len(YUL_PREFIX):])
    elif s.startswith(RAW_PREFIX):
        from compilers.raw import compile_raw
        return compile_raw(s[len(RAW_PREFIX):])
    elif s.startswith(SOLIDITY_PREFIX):
        raise Exception("solidity not yet supported")
    elif s.startswith(ABI_PREFIX):
        raise Exception("abi not valid as code")
    else:
        from compilers.lll import compile_lll
        return compile_lll(s)