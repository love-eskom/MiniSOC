"""
MiniSOC Event Model

Defines the normalized event structure used internally by MiniSOC.

An EventSchema represents a security-relevant event produced by a
telemetry source such as Linux authentication logs, firewall logs,
Windows Event Logs, web server logs, or packet captures.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class EventSchema:
    """    
    Normalised representation of a security event.
    
    Required fields:
        timestamp: When did the event occur.
        event_type: type of event.
        
    optional fields:
        source_ip: IP address that initiated the event.
        destination_ip: IP address targeted. 
        destination port: Virtual destination interface.
        user: User associated with the event.
        status: result of the event.
    """

    # Required fields
    timestamp: datetime
    event_type: str

    # Optional fields
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    user: Optional[str] = None
    status: Optional[str] = None