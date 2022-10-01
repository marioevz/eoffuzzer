from subprocess import Popen, PIPE
"""
Compiles string code using `solc --assemble` compiler.
"""
def compile_yul(code: str) -> bytearray:
    cmd = ['solc', '--assemble', '-']
    p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=PIPE)
    output_lines = p.communicate(input=code.encode())[0].decode('utf-8').split('\n')
    binary_repr = output_lines[output_lines.index('Binary representation:')+1]
    return bytearray.fromhex(binary_repr)