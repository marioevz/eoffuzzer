from abc import ABC, abstractmethod
from typing import Any, Dict
from compilers import compile

"""
Base abstract class for the container of any version.
"""
class Container(ABC):
    @abstractmethod
    def build(self) -> bytearray:
        pass
    
    @abstractmethod
    def is_valid(self) -> bool:
        pass

    @abstractmethod
    def get_name(self) -> str:
        pass

    @abstractmethod
    def get_description(self) -> str:
        pass

    @abstractmethod
    def get_seed(self) -> int:
        pass

"""
Parses a dict by calling the appropriate compiler for the version of the EOF
"""
def compile_from_dict(source_dict: Dict[str, Any]) -> Container:
    # Default version is 1
    version = 1
    if 'version' in source_dict:
        version = source_dict['version']

    if version == 1:
        from eof.v1 import compile_v1_from_dict
        return compile_v1_from_dict(source_dict, compile_from_dict, compile)
    else:
        raise Exception("invalid version")