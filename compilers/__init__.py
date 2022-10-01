import sys
def compile(s: str) -> bytearray:
    YUL_PREFIX = ":yul"
    RAW_PREFIX = ":raw"
    SOLIDITY_PREFIX = ":solidity"
    ABI_PREFIX = ":abi"
    if s.startswith(YUL_PREFIX):
        from compilers.yul import compile_yul
        return compile_yul(s[len(YUL_PREFIX):])
    else:
        print("warn: no compiler found", file=sys.stderr)
        print(s, file=sys.stderr)
    return bytearray()