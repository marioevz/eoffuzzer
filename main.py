#!/usr/bin/env python

## EVM Object Format fuzzer creator
import sys
import argparse
import random
from enum import IntEnum, auto
from typing import Optional

def getOptions(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Output a fuzzed ")
    parser.add_argument("-o", "--output")
    parser.add_argument("-s", "--seed", help="Seed used to produce the bytecode. Default=random")
    parser.add_argument("-v", "--version", help="Version number of the EVM Object Format. Default=1", default=1)
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
print("Using seed:", hex(current_seed))

if opts.version == 1:
    from eof.v1 import generate_container
else:
    raise Exception("Invalid version")

c = generate_container(seed=opts.seed)
print("Generated EOF container: ", c.build().hex())