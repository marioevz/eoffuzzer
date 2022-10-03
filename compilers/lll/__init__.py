from subprocess import Popen, PIPE
"""
Compiles lll code string using `lllc` compiler.
"""
def compile_lll(code: str) -> bytearray:
    cmd = ['lllc']
    p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    binary_repr = p.communicate(input=code.encode())[0].decode('utf-8')
    if not binary_repr:
        raise Exception('invalid code')
    return bytearray.fromhex(binary_repr)