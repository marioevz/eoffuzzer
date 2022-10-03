# EVM Object Utilities

Currently supports the only available version: V1

###  Usage

```
./main.py <command> [<command options>]
```

Options: see `./main.py -h`
## Fuzzer

Generates random valid or invalid EOF containers.



## Compiler Format

The compiler takes a single file in the YML format with the following structure:
```
version: 1
sections:
- code: ':yul { stop() }'
- data:
    version: 1
    sections:
    - code: |
        :yul
        {
        stop()
        }
```

`data` and `code` sections can be either:
- A bytecode source with the prefixed compiler to be used (`:yul`, `:raw`, `:solidity`)
- An object of a subcontainer using the same format

Top-level extra fields can be:
- `mock-version`: a number in the range `0x00-0xff` of the value to mock instead of the expected `0x01` for the version number.
- `mock-magic`: a number in the range `0x00-0xff` of the value to mock instead of the expected `0x00` of the magic number.

Each section can have the following optional extra fields:
- `mock-kind`: a number in the range `0x00-0xff` of the value to mock instead of `0x01` for code or `0x02` for data.
- `mock-size`: a number in the range `0x0000-0xffff` of the value to mock instead of the correct size for the section.