#!/usr/bin/env python
import sys
import yaml
from yaml import Loader

if len(sys.argv) < 2:
    raise Exception("invalid arguments")
(_, srcfile) = sys.argv

lines = None
with open(srcfile) as f:
    lines = f.read().splitlines()

if not lines:
    raise Exception("invalid input")

# First line is the version
v = lines.pop(0)

if v.lower() != 'v1':
    raise Exception("invalid version")

l = yaml.load('\n'.join(lines), Loader=Loader)

from compilers import compile
from eof.v1 import compile_from_dict

c = compile_from_dict(l, compile)

print('0x' + c.build().hex())