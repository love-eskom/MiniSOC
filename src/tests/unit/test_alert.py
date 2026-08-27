"""
Tests Alert creation and default behavior.

- Verifies Alert fields are stored correctly.
- Verifies optional fields default to None.
- Verifies contributing events are stored correctly.
"""

from datetime import datetime
from minisoc.models.alert import Alert, EventSchema

timestamp = datetime.now()

def test_alert_creation():
    alert = Alert(
        timestamp= timestamp,
        rule_id= "Rule 101",
        severity="HIGH",
        alert_type="brute force",
        description="brute",
        source_ip="192.168.10.1",
        user="admin"
    )
    
    assert alert.rule_id == "Rule 101"
    assert alert.timestamp == timestamp
    assert alert.severity == "HIGH" 
    assert alert.source_ip == "192.168.10.1"
    assert alert.user == "admin"
    assert alert.alert_type == "brute force"
    assert alert.description == "brute"
    
def test_optional_fields():
    """
    Test if optional fields default to none if no value is supplied
    """
    alert =    Alert (
        rule_id="Rule 102",
        severity="High",
        alert_type="XSS",
        description="",
        timestamp=timestamp,
    )
    
    
    assert alert.source_ip is None
    assert alert.destination_ip is None
    assert alert.user is None

def test_evidence():
    event1 = EventSchema(
                timestamp=timestamp,
                event_type="SSH login attempt",
                source_ip="168.145.60.7",
                destination_ip="192.168.9.11",
                status="Failed"
            )
    
    event2 = EventSchema(
                timestamp=timestamp,
                event_type="Port scan",
                source_ip="192.168.4.5",
                destination_ip="192.168.9.1"
            )

    alert = Alert (
        rule_id="Rule 106",
        severity="High",
        alert_type="Failed SSH login",
        description="",
        timestamp=timestamp,
        events=[event1, event2]
    )

    assert len(alert.events) == 2
    assert alert.events[0] == event1
    assert alert.events[1] == event2
    assert alert.events == [event1, event2]

from datetime import datetime
from minisoc.models.alert import Alert
from minisoc.models.event import EventSchema


def test_alerts_have_independent_event_lists():
    """Verify each Alert gets its own unique list instance for events."""
    timestamp = datetime.now()

    alert1 = Alert(
        timestamp=timestamp,
        rule_id="RULE-101",
        severity="HIGH",
        alert_type="brute_force",
        description="Brute force attack detected" # Added missing required field
    )
    alert2 = Alert(
        timestamp=timestamp,
        rule_id="RULE-102",
        severity="LOW",
        alert_type="port_scan",
        description="Port scan detected"          # Added missing required field
    )

    # Append an event only to alert1
    # Note: Ensure EventSchema arguments also match its actual signature
    event = EventSchema(timestamp=timestamp, event_type="authentication_failure")
    alert1.events.append(event)

    assert len(alert1.events) == 1
    assert len(alert2.events) == 0
    assert alert1.events is not alert2.events  
