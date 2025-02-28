from typing import List, Tuple
from dataclasses import dataclass

class AddonProperites:
    
    def __init__(self, name:str, ver:str="Unspecified", author:str="Unknown", website:str="Unspecified", shortDesc:str="No addon description found.", requiresExternal:bool=False, internalAddon:bool=False):
        self.ver: str = ver
        self.name: str = name
        self.author: str = author
        self.website: str = website
        self.shortDesc: str = shortDesc
        self.internalAddon:bool = internalAddon
        self.requiresExternal: bool = requiresExternal
    
    def add_require_package(self, name, version):
        toAdd = (name, version)

@dataclass  
class ExternalDependencies:
    # These are dependancies like with pip3
    
    
    # expected to be a name and version number
    package:List[Tuple[str, str]] = []
    satisfaction:bool
    
@dataclass
class InternalDependancies:
    # This is a PLV Addon. So, if SMSQL needs another locally installed PLV addon.
    
    # expected to be a name and version number
    package:List[Tuple[str, str]] = []
    satisfaction:bool