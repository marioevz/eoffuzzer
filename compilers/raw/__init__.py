"""
Converts a raw string to a bytearray.
"""
def compile_raw(code: str) -> bytearray:
    code = code.strip()
    if code.startswith('0x'):
        code = code[2:]
    return bytearray.fromhex(code)