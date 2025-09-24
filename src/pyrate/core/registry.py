from pyrate.utils import Module

from typing import Optional, Dict, List
from dataclasses import dataclass

@dataclass
class RegistryConfig:
    plugins_path: Optional[str] = "./plugins"

class Registry:
    register: Optional[List[Module]] = []
    
    def __init__(self, config: RegistryConfig):
        self.config = config