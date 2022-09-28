import random
from enum import IntEnum, IntFlag, auto
from typing import Optional, Union, List

EOF_HEADER_TERMINATOR = 0
EOF_MAGIC = 0
EOF_V1_VERSION_NUMBER = 1

# Valid EOF format:
# magic, version, (section_kind, section_size)+, 0, <section contents>
MAX_CODE_SIZE = int('0x6000', 16)

# EOFV1 or legacy initcodes must fail when they attempt to launch an EOFV1 code
# container with any of the following invalidity types
class InvalidityType(IntFlag):
    # Magic
    INVALID_MAGIC           = auto()

    # EOF Version
    INVALID_VERSION         = auto()

    # Sections
    EMPTY_SECTIONS          = auto()

    INVALID_SECTION_KIND    = auto()

    INVALID_SECTION_SIZE    = auto()
    
    INVALID_TRAILING_BYTES  = auto()

    NO_CODE_SECTION         = auto()
    TOO_MANY_CODE_SECTIONS  = auto()
    TOO_MANY_DATA_SECTIONS  = auto()
    DATA_SECTION_FIRST      = auto()

    MAX_INVALIDITY          = auto()

class SectionKindV1(IntEnum):
    CODE = 1
    DATA = 2

class Section(object):
    """
    Data to be contained by this section.
    Can be code or any abstract data.
    """
    data: Optional[bytearray]=None
    """
    Size value to be used in the header.
    If set to None, the header is built with length of the data.
    """
    size: Optional[int]=None
    """
    Name used to reference this container.
    """
    name: Optional[str]=None
    kind: Union[SectionKindV1, int]

    def __init__(self, kind: Union[SectionKindV1, int]):
        self.kind = kind

    """
    Sets a fixed number as size.
    Only to be called when a spoof size needs to be used for testing purposes.
    """ 
    def set_size(self, size: int):
        self.size = size
    
    """
    Sets the information contained in this section.
    """ 
    def set_body(self, data: bytearray):
        self.data = data

    """
    Gets the formatted header for this section.
    """ 
    def get_header(self) -> bytearray:
        size = self.size
        if size is None:
            if self.data is None:
                raise Exception("Attempted to build header without section data")
            size = len(self.data)
        return self.kind.to_bytes(1, byteorder='big') + size.to_bytes(2, byteorder='big')

    """
    Gets the body of the section.
    """ 
    def get_body(self) -> bytearray:
        return self.data

    def __str__(self) -> str:
        return 'kind={}, len(data)={}'.format(str(self.kind), len(self.data))

class Container(object):
    sections: List[Section]
    magic: Optional[int]=None
    version: Optional[int]=None
    """
    Extra data to be appended at the end of the container, which will
    not be considered part of any of the sections.
    If not None, the container is invalidated for testing purposes.
    """
    extra: Optional[bytearray]=None
    valid: bool
    description: Optional[str]=None
    seed: Optional[int]=None

    def __init__(self):
        self.sections = []
        self.valid = True

    """
    Override to get the byte length of the full container
    """
    def __len__(self):
        l = 2  # EOF Magic 0xEF00
        l += 1 # EOF Version 0x01
        l += 3 * len(self.sections) # kind + size of each section
        l += 1 # Section Headers Terminator 0x00
        for s in self.sections:
            if s.data:
                l += len(s.data)
        return l

    """
    Adds a section to the container.
    """ 
    def add_section(self, section: Section):
        if not self.sections:
            self.sections = []
        self.sections.append(section)
    
    """
    Calculates the byte length a new section could have without
    overflowing the `MAX_CODE_SIZE` limit.
    """ 
    def remaining_space(self):
        current_space_used = 2  # EOF Magic 0xEF00
        current_space_used += 1 # EOF Version 0x01
        current_space_used += 1 # Section Headers Terminator 0x00
        current_space_used += 3 * (len(self.sections) + 1)
        for s in self.sections:
            current_space_used += len(s.data)
        if current_space_used >= MAX_CODE_SIZE:
            return 0
        return MAX_CODE_SIZE - current_space_used

    def has_data_section(self) -> bool:
        for s in self.sections:
            if s.kind == SectionKindV1.DATA:
                return True
        return False
    
    def first_data_section_index(self) -> int:
        for i, s in enumerate(self.sections):
            if s.kind == SectionKindV1.DATA:
                return i
        return -1

    """
    Builds the byte array that represents the entire EOF container.
    """ 
    def build(self) -> bytearray:
        c = bytearray.fromhex("EF")

        magic = self.magic
        if magic is None:
            magic = EOF_MAGIC
        c.append(magic)

        version = self.version
        if version is None:
            version = EOF_V1_VERSION_NUMBER
        c.append(version)
        
        # Add headers
        for s in self.sections:
            c += s.get_header()

        # Add header terminator
        c.append(EOF_HEADER_TERMINATOR)

        # Add section bodies
        for s in self.sections:
            c += s.get_body()

        # Add extra (garbage)
        if not self.extra is None:
            c += self.extra

        return c
    
    """
    Returns the keccak256 hash of the container.
    """
    def keccak256(self) -> bytearray:
        pass


    def __str__(self) -> str:
        return 'magic={}, sections=[{}]'.format(self.magic, ','.join([str(s) for s in self.sections]))

"""
Generate a container using the specified parameters.
Generated container will try to stay within the boundaries of
`MAX_CODE_SIZE`, unless a specific code is used that by itself
overflows the limit.
"""
def generate_container(seed: int, code: Optional[bytearray]=None, code_size: Optional[int]=None, data: Optional[bytearray]=None, data_size: Optional[int]=None, inv_type: Optional[InvalidityType]=InvalidityType(0)) -> Container:
    # Init randomness for this subroutine
    random.seed(seed)

    # Valid EOFV1 containers must have the following format:
    # 0x EF00 01 01 <code section size> [02 <data section size>] 00 <code section> [<data section>]

    c = Container()
    c.seed = seed

    if inv_type == 0:
        c.description = "Valid EOF V1 container"
    else:
        c.description = "Invalid EOF V1 container"
        c.valid = False
    

    if InvalidityType.INVALID_MAGIC in inv_type:
        c.magic = random.randint(EOF_MAGIC+1, 0xff)
        c.description += "\n- Invalid MAGIC={}".format(c.magic)
        

    if InvalidityType.INVALID_VERSION in inv_type:
        c.version = random.randint(EOF_V1_VERSION_NUMBER+1, 0xfe)
        if c.version >= EOF_V1_VERSION_NUMBER:
            c.version += 1
        c.description += "\n- Invalid VERSION={}".format(c.version)

    if not InvalidityType.EMPTY_SECTIONS in inv_type:
        # TODO: Fill Sections
        if not InvalidityType.NO_CODE_SECTION in inv_type:
            # Insert at least 1 code section
            cs = Section(SectionKindV1.CODE)
            if not code is None:
                # Parameters provided code to introduce
                cs.data = code
            else:
                if code_size is None:
                    # No code nor size specified
                    code_size = random.randint(1, c.remaining_space())
                cs.data = random.randbytes(code_size)
            c.add_section(cs)

            if InvalidityType.TOO_MANY_CODE_SECTIONS in inv_type:
                # Insert another code section
                cs = Section(SectionKindV1.CODE)
                new_code_size = random.randint(0, c.remaining_space())
                cs.data = random.randbytes(new_code_size)
                c.add_section(cs)
                c.description += "\n- Invalid due to TOO MANY CODE SECTIONS"
        else:
            c.description += "\n- Invalid due to NO CODE SECTION"

        if c.remaining_space() > 0 or \
            not data is None or \
            not data_size is None or \
            InvalidityType.TOO_MANY_DATA_SECTIONS in inv_type:
            ds = Section(SectionKindV1.DATA)
            if not data is None:
                ds.data = data
            else:
                if data_size is None:
                    data_size = random.randint(1, c.remaining_space())
                ds.data = random.randbytes(data_size)
            c.add_section(ds)
            
            if InvalidityType.TOO_MANY_DATA_SECTIONS in inv_type:
                # Insert another data section
                ds = Section(SectionKindV1.DATA)
                new_code_size = random.randint(0, c.remaining_space())
                ds.data = random.randbytes(new_code_size)
                c.add_section(ds)
                c.description += "\n- Invalid due to TOO MANY DATA SECTIONS"
    else:
        c.description += "\n- Invalid due to ZERO SECTIONS"


    
    if len(c.sections) > 0:
        if InvalidityType.DATA_SECTION_FIRST in inv_type:
            if c.has_data_section():
                data_idx = c.first_data_section_index()
                data_section = c.sections.pop(data_idx)
                c.sections.insert(0, data_section)
            else:
                # There is no data section,
                # change kind of first section to data
                c.sections[0].kind = SectionKindV1.DATA
            c.description += "\n- Invalid due to DATA SECTION APPEARS FIRST"

        if InvalidityType.INVALID_SECTION_KIND in inv_type:
            section_index = random.randint(0, len(c.sections) - 1)
            c.sections[section_index].kind = random.randint(0, 0xfd)
            if c.sections[section_index].kind >= SectionKindV1.CODE.value:
                c.sections[section_index].kind += 2
            c.description += "\n- Invalid due to section_kind={}".format(c.sections[section_index].kind)

        if InvalidityType.INVALID_SECTION_SIZE in inv_type:
            section_index = random.randint(0, len(c.sections) - 1)
            c.sections[section_index].size = random.randint(0, 0xfffe)
            if c.sections[section_index].size >= len(c.sections[section_index].data):
                c.sections[section_index].size += 1
            c.description += "\n- Invalid due to section_size={}!={}".format(c.sections[section_index].size, len(c.sections[section_index].data))

    if InvalidityType.INVALID_TRAILING_BYTES in inv_type:
        c.extra = random.randbytes(2)
        c.description += "\n- Invalid due to trailing bytes={}".format(c.extra.hex())
    valid_str = 'valid'
    if not c.valid:
        valid_str = 'invalid'
    c.name = 'eofV1_{}_{}'.format(hex(seed)[2:], valid_str)
    return c

"""
Generates a simple legacy initcode to return a bytecode.
"""
def generate_legacy_initcode(code: bytearray) -> bytearray:
    
    if len(code) >= 2**16:
        raise Exception("code too long for init code")

    initcode = bytearray()

    # PUSH2 - length - length of the code
    initcode.append(0x61)
    initcode += len(code).to_bytes(2, byteorder='big')

    # PUSH2 - offset - length of these opcodes
    initcode.append(0x61)
    opcodes_length_position = len(initcode)
    initcode.append(0x00)
    initcode.append(0x00)

    # PUSH1 (0x00) - destOffset
    initcode.append(0x60)
    initcode.append(0x00)

    # CODECOPY
    initcode.append(0x39)

    # PUSH2 - length - length of the code
    initcode.append(0x61)
    initcode += len(code).to_bytes(2, byteorder='big')

    # PUSH1 (0x00) - offset
    initcode.append(0x60)
    initcode.append(0x00)

    # RETURN
    initcode.append(0xF3)

    # Overwrite opcodes length with current actual length
    initcode_length = len(initcode).to_bytes(2, byteorder='big')
    initcode[opcodes_length_position] = initcode_length[0]
    initcode[opcodes_length_position+1] = initcode_length[1]

    # Finally add the code
    initcode += code
    return initcode

"""
Generates a EOF V1 initcode containing the inialization code and the
output bytecode as a data section.
"""
def generate_eof_container_initcode(code: bytearray) -> bytearray:
    if len(code) >= 2**16:
        raise Exception("code too long for init code")

    c = Container()

    cs = Section(SectionKindV1.CODE)
    ds = Section(SectionKindV1.DATA)
    c.add_section(cs)
    c.add_section(ds)

    # Build the init code
    cs.data = bytearray()

    # PUSH2 - length - length of the code
    cs.data.append(0x61)
    cs.data += len(code).to_bytes(2, byteorder='big')

    # PUSH2 - offset - length of these opcodes
    cs.data.append(0x61)
    opcodes_length_position = len(cs.data)
    cs.data.append(0x00)
    cs.data.append(0x00)

    # PUSH1 (0x00) - destOffset
    cs.data.append(0x60)
    cs.data.append(0x00)

    # CODECOPY
    cs.data.append(0x39)

    # PUSH2 - length - length of the code
    cs.data.append(0x61)
    cs.data += len(code).to_bytes(2, byteorder='big')

    # PUSH1 (0x00) - offset
    cs.data.append(0x60)
    cs.data.append(0x00)

    # RETURN
    cs.data.append(0xF3)

    # Overwrite opcodes length with current actual length
    initcode_length = len(c).to_bytes(2, byteorder='big')
    cs.data[opcodes_length_position] = initcode_length[0]
    cs.data[opcodes_length_position+1] = initcode_length[1]

    # Finally add the code to the data section
    ds.data = code

    return c.build()