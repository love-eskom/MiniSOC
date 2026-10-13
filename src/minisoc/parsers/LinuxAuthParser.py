from datetime import datetime 
from base import BaseParser
from minisoc.models.event import EventSchema
from typing import Optional
import re

class LinuxAuthParser(BaseParser):
    SSH_PATTERN = re.compile(
            r"(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
            r"(?P<status>Accepted|Failed)\s+password\s+for\s+(?P<user>\S+)\s+from\s+(?P<source_ip>\S+)\S+"
        )
    
    def parse_line(self, raw_line: str) -> Optional[EventSchema]:
        
        match = self.SSH_PATTERN.search(raw_line)
        if not match:
            return None
        
        data = match.groupdict()
        
        current_year = datetime.now().year
        timestamp_str = f"{current_year} {data['timestamp']}"
        
        try:
            timestamp_dt = datetime.striptm(timestamp_str, "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        
        status = "Success" if data["status"] == "Accepted" else "Failed"
        
        return EventSchema(
            timestamp=timestamp_dt,
            event_type="SSH AUTHENTICATION",
            user=data['user'],
            status=status,
            source_ip=data['source_ip']
        )