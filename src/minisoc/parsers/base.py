"""
Base parser abstraction for MiniSOC.

Defines the common interface that all log parsers
must implement.
"""

from abc import ABC, abstractmethod
from minisoc.models.event import EventSchema

class BaseParser(ABC):
    """
    Abstract base class for MiniSOC log parsers.

    Every concrete parser must implement parse_line()
    and return a normalized EventSchema.
    """
    
    @abstractmethod
    
    
    def parse_line(self, raw_line: str) -> EventSchema:
        """
            Parse a raw log line into a normalized EventSchema.

            Args:
                raw_line: Raw log entry from the source.

            Returns:
                A normalized EventSchema object.
        """
        pass