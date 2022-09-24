import random
from enum import IntFlag, auto
from typing import Optional, List

EOF_HEADER_TERMINATOR = 0
EOF_MAGIC = 0
EOF_V1_VERSION_NUMBER = 1
EOF_V1_SECTION_KIND_CODE = 1
EOF_V1_SECTION_KIND_DATA = 2

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

class Section(object):
    data: Optional[bytearray]=None
    size: Optional[int]=None
    kind: int

    def __init__(self, kind: int):
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
        if self.size is None:
            if self.data is None:
                raise Exception("Attempted to build head without section data")
            self.size = len(self.data)
        return self.kind.to_bytes(1, byteorder='big') + self.size.to_bytes(2, byteorder='big')

    """
    Gets the body of the section.
    """ 
    def get_body(self) -> bytearray:
        return self.data

class Container(object):
    sections: List[Section]
    magic: Optional[int]=None
    version: Optional[int]=None
    extra: Optional[bytearray]=None

    def __init__(self):
        self.sections = []

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
            if s.kind == EOF_V1_SECTION_KIND_DATA:
                return True
        return False
    
    def first_data_section_index(self) -> int:
        for i, s in enumerate(self.sections):
            if s.kind == EOF_V1_SECTION_KIND_DATA:
                return i
        return -1

    """
    Builds the byte array that represents the entire EOF container.
    """ 
    def build(self) -> bytearray:
        c = bytearray.fromhex("EF")

        if self.magic is None:
            self.magic = EOF_MAGIC
        c.append(self.magic)

        if self.version is None:
            self.version = EOF_V1_VERSION_NUMBER
        c.append(self.version)
        
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

    if InvalidityType.INVALID_MAGIC in inv_type:
        c.magic = random.randint(EOF_MAGIC+1, 0xff)

    if InvalidityType.INVALID_VERSION in inv_type:
        c.version = random.randint(EOF_V1_VERSION_NUMBER+1, 0xfe)
        if c.version >= EOF_V1_VERSION_NUMBER:
            c.version += 1

    if not InvalidityType.EMPTY_SECTIONS in inv_type:
        # TODO: Fill Sections
        if not InvalidityType.NO_CODE_SECTION in inv_type:
            # Insert at least 1 code section
            cs = Section(EOF_V1_SECTION_KIND_CODE)
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
                cs = Section(EOF_V1_SECTION_KIND_CODE)
                new_code_size = random.randint(0, c.remaining_space())
                cs.data = random.randbytes(new_code_size)
                c.add_section(cs)
        
        if c.remaining_space() > 0 or \
            not data is None or \
            not data_size is None or \
            InvalidityType.TOO_MANY_DATA_SECTIONS in inv_type:
            ds = Section(EOF_V1_SECTION_KIND_DATA)
            if not data is None:
                ds.data = data
            else:
                if data_size is None:
                    data_size = random.randint(0, c.remaining_space())
                ds.data = random.randbytes(data_size)
            c.add_section(ds)
            
            if InvalidityType.TOO_MANY_DATA_SECTIONS in inv_type:
                # Insert another data section
                ds = Section(EOF_V1_SECTION_KIND_DATA)
                new_code_size = random.randint(0, c.remaining_space())
                ds.data = random.randbytes(new_code_size)
                c.add_section(ds)
            
    
    if len(c.sections) > 0:
        if InvalidityType.DATA_SECTION_FIRST in inv_type:
            if c.has_data_section:
                data_idx = c.first_data_section_index()
                data_section = c.sections.pop(data_idx)
                c.sections.insert(0, data_section)
            else:
                # There is no data section,
                # change kind of first section to data
                c.sections[0].kind = EOF_V1_SECTION_KIND_DATA

        if InvalidityType.INVALID_SECTION_KIND in inv_type:
            section_index = random.randint(0, len(c.sections) - 1)
            c.sections[section_index].kind = random.randint(0, 0xfd)
            if c.sections[section_index].kind >= EOF_V1_SECTION_KIND_CODE:
                c.sections[section_index].kind += 2
        
        if InvalidityType.INVALID_SECTION_SIZE in inv_type:
            section_index = random.randint(0, len(c.sections) - 1)
            c.sections[section_index].size = random.randint(0, 0xfe)
            if c.sections[section_index].kind >= len(c.sections[section_index].data):
                c.sections[section_index].kind += 1

    if InvalidityType.INVALID_TRAILING_BYTES in inv_type:
        c.extra = random.randbytes(2)

    return c