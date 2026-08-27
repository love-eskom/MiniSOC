"""
Tests for the MiniSOC EventSchema model.
"""

from datetime import datetime

from minisoc.models.event import EventSchema


def test_event_creation():
    """Test that a valid EventSchema can be created."""

    timestamp = datetime.now()

    event = EventSchema(
        timestamp=timestamp,
        event_type="authentication",
        source_ip="192.168.1.50",
        user="admin",
        status="failure",
    )

    assert event.timestamp == timestamp
    assert event.event_type == "authentication"
    assert event.source_ip == "192.168.1.50"
    assert event.user == "admin"
    assert event.status == "failure"


def test_optional_fields_default_to_none():
    """Test that optional fields default to None."""

    event = EventSchema(
        timestamp=datetime.now(),
        event_type="authentication",
    )

    assert event.source_ip is None
    assert event.destination_ip is None
    assert event.destination_port is None
    assert event.user is None
    assert event.status is None
    

def test_event_representation():
    event = EventSchema(timestamp=datetime.now(),source_ip="192.168.1.9", event_type="brute force")
    
    assert "brute force" in repr(event.event_type)
    assert "192.168.1.9" in repr(event.source_ip)
    
