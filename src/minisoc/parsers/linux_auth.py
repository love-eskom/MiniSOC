
"""
Linux SSH authentication log parser for MiniSOC.

Extracts successful and failed SSH password-authentication
events and normalizes them into EventSchema objects.
"""

import re
import ipaddress
from datetime import datetime

from minisoc.models.event import EventSchema
from minisoc.parsers.base import BaseParser


class LinuxAuthParser(BaseParser):
    """Parse Linux sshd password-authentication log entries."""

    SSH_PATTERN = re.compile(
        r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
        r"\s+\S+\s+sshd\[\d+\]:\s+"
        r"(?P<status>Accepted|Failed)\s+password\s+for\s+"
        r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+"
        r"(?P<source_ip>\S+)"
    )

    def parse_line(self, raw_line: str) -> EventSchema | None:
        """Return a normalized event, or None if the line is unusable."""

        match = self.SSH_PATTERN.search(raw_line)

        # Ignore unrelated or unrecognized log entries.
        if match is None:
            return None

        data = match.groupdict()

        # Reject invalid IP addresses.
        try:
            source_ip = str(ipaddress.ip_address(data["source_ip"]))
        except ValueError:
            return None

        # Syslog timestamps omit the year.
        timestamp_text = f"{datetime.now().year} {data['timestamp']}"

        try:
            timestamp = datetime.strptime(
                timestamp_text,
                "%Y %b %d %H:%M:%S",
            )
        except ValueError:
            return None

        status = "Success" if data["status"] == "Accepted" else "Failed"

        return EventSchema(
            timestamp=timestamp,
            event_type="SSH authentication",
            user=data["user"],
            source_ip=source_ip,
            status=status,
        )
