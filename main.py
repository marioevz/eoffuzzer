#!/usr/bin/env python

## EVM Object Format fuzzer creator
import sys
import argparse

def get_options(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="EOF Utilities")
    subparsers = parser.add_subparsers(dest="subcommand_name", required=True)

    fuzzer = subparsers.add_parser("fuzzer", help="Output a fuzzed EOF container with or without an initcode (EOF/Legacy). Optionally create a yml file with a \"ethereum/tests\" test.")
    fuzzer.add_argument("-s", "--seed", help="Hex seed used to produce the container. Default=random")
    fuzzer.add_argument("--codesize", help="Size of the random code section's data. Default=random([1,MAX_CODE_SIZE])", type=int)
    fuzzer.add_argument("--datasize", help="Size of the random data section's data. Default=random([1,MAX_CODE_SIZE])", type=int)
    fuzzer.add_argument("-v", "--version", help="Version number of the EVM Object Format. Default=1", default=1)
    fuzzer.add_argument("-i", "--initcode", help="Produce legacy initcode for the EOF container. Default=No", action='store_true')
    fuzzer.add_argument("--eof-initcode", help="Produce EOF initcode for the EOF container. Default=No", action='store_true')
    fuzzer.add_argument("-f", "--filler", help="Produce the test filler in yml format. Default=No", action='store_true')
    fuzzer.add_argument("--create-method", help="Specify how the filler should create the contract (tx, create or create2). Default=tx", type=str, default='tx')
    fuzzer.add_argument("--invalidity-type", help="Produce an invalid EOF container. Use -1 to generate a random invalidity type. Default=0.", type=int)
    ## TODO: Add invalidity types as arguments here too

    compile = subparsers.add_parser("compile", help="Compile a YML file into an EOF container")
    compile.add_argument("ymlfile", help="Source YML file.")

    options = parser.parse_args(args)
    return options

def exec_fuzzer(opts):
    import random
    # Check version requested
    if opts.version and opts.version != 1:
        raise Exception("Invalid version requested (only version 1 supported)")

    # Random seed will be used to try to replicate the same initcode twice
    if opts.seed:
        if not type(opts.seed) is str:
            raise Exception("invalid input")
        if not opts.seed.startswith("0x"):
            opts.seed = "0x" + opts.seed
        opts.seed = int(opts.seed, 16)
    else:
        from time import time
        opts.seed = int(time() * 1000000)

    current_seed = opts.seed
    random.seed(current_seed)

    if opts.version == 1:
        from eof.v1 import generate_container, InvalidityType
    else:
        raise Exception("Invalid version")

    if opts.invalidity_type is None:
        opts.invalidity_type = 0
    elif opts.invalidity_type == -1:
        # Produce a container with random and multiple types of invalid characteristics
        opts.invalidity_type = random.randint(1, InvalidityType.MAX_INVALIDITY - 1)
    elif opts.invalidity_type == -2:
        # Produce a container with a single random invalid characteristic
        inv_types_count = len(bin(InvalidityType.MAX_INVALIDITY)[3:]) - 1
        opts.invalidity_type = InvalidityType(2 ** random.randint(0, inv_types_count))

    opts.invalidity_type=InvalidityType(opts.invalidity_type)

    c = generate_container(seed=opts.seed, code_size=opts.codesize, data_size=opts.datasize, inv_type=opts.invalidity_type)


    if opts.filler:
        from filler import generate_filler
        initcode_f = None
        if opts.eof_initcode:
            from eof.v1 import generate_legacy_initcode
            initcode_f = generate_legacy_initcode
        else:
            from eof.v1 import generate_eof_container_initcode
            initcode_f = generate_eof_container_initcode
        print(generate_filler(c, initcode_f, opts.create_method))
    else:
        print("Generated EOF container: ", c.build().hex())
        if opts.initcode or opts.eof_initcode:
            if opts.eof_initcode:
                from eof.v1 import generate_eof_container_initcode
                initcode = generate_eof_container_initcode(c.build())
                print("Generated EOF container EOF V1 initcode: ", initcode.hex())
            else:
                from eof.v1 import generate_legacy_initcode
                initcode = generate_legacy_initcode(c.build())
                print("Generated EOF container legacy initcode: ", initcode.hex())

def exec_compiler(opts):
    import yaml
    from yaml import Loader

    lines = None
    with open(opts.ymlfile) as f:
        lines = f.read().splitlines()

    if not lines:
        raise Exception("invalid input")

    l = yaml.load('\n'.join(lines), Loader=Loader)

    version = 1
    if 'version' in l:
        version = l['version']

    if version != 1:
        raise Exception("invalid version")

    from compilers import compile
    from eof.v1 import compile_from_dict

    c = compile_from_dict(l, compile)

    print('0x' + c.build().hex())

opts = get_options()

if opts.subcommand_name == "fuzzer":
    exec_fuzzer(opts)
elif opts.subcommand_name == "compile":
    exec_compiler(opts)