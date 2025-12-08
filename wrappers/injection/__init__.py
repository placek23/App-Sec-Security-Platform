# Injection wrappers
from .sqlmap import SqlmapWrapper
from .dalfox import DalfoxWrapper
from .commix import CommixWrapper
from .tplmap import TplmapWrapper

__all__ = [
    'SqlmapWrapper',
    'DalfoxWrapper',
    'CommixWrapper',
    'TplmapWrapper'
]
