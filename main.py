#!/usr/bin/env python

## EVM Object Format fuzzer creator
import sys
import argparse
import random

def getOptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Output a fuzzed EOF container with or without an initcode (EOF/Legacy)")
    parser.add_argument("-s", "--seed", help="Hex seed used to produce the container. Default=random")
    parser.add_argument("--codesize", help="Size of the random code section's data. Default=random([1,MAX_CODE_SIZE])", type=int)
    parser.add_argument("--datasize", help="Size of the random data section's data. Default=random([1,MAX_CODE_SIZE])", type=int)
    parser.add_argument("-v", "--version", help="Version number of the EVM Object Format. Default=1", default=1)
    parser.add_argument("-i", "--initcode", help="Produce legacy initcode for the EOF container. Default=No", action='store_true')
    parser.add_argument("--eof-initcode", help="Produce EOF initcode for the EOF container. Default=No", action='store_true')
    parser.add_argument("-f", "--filler", help="Produce the test filler in yml format. Default=No", action='store_true')
    parser.add_argument("--create-method", help="Specify how the filler should create the contract (tx, create or create2). Default=tx", type=str, default='tx')
    parser.add_argument("--invalidity-type", help="Produce an invalid EOF container. Use -1 to generate a random invalidity type. Default=0.", type=int)
    ## TODO: Add invalidity types as arguments here too
    options = parser.parse_args(args)
    return options

opts = getOptions()

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