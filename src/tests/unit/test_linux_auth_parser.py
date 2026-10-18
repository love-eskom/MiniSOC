
from datetime import datetime

import pytest

from minisoc.models.event import EventSchema
from minisoc.parsers.linux_auth import LinuxAuthParser


@pytest.fixture
def parser():
    return LinuxAuthParser()


def test_parse_failed_ssh_login(parser):
    raw_line = (
        "Aug 29 18:42:13 server sshd[1234]: "
        "Failed password for admin from 192.168.1.50 "
        "port 54321 ssh2"
    )

    event = parser.parse_line(raw_line)

    assert isinstance(event, EventSchema)
    assert event.user == "admin"
    assert event.source_ip == "192.168.1.50"
    assert event.event_type == "SSH authentication"
    assert event.status == "Failed"
    assert isinstance(event.timestamp, datetime)


def test_parse_successful_ssh_login(parser):
    raw_line = (
        "Aug 29 18:45:22 server sshd[1234]: "
        "Accepted password for admin from 192.168.1.50 "
        "port 54321 ssh2"
    )

    event = parser.parse_line(raw_line)

    assert isinstance(event, EventSchema)
    assert event.user == "admin"
    assert event.source_ip == "192.168.1.50"
    assert event.event_type == "SSH authentication"
    assert event.status == "Success"


def test_parse_invalid_user_attempt(parser):
    raw_line = (
        "Aug 29 18:42:13 server sshd[1234]: "
        "Failed password for invalid user ghost from "
        "192.168.1.50 port 54321 ssh2"
    )

    event = parser.parse_line(raw_line)

    assert isinstance(event, EventSchema)
    assert event.user == "ghost"
    assert event.status == "Failed"


def test_unrelated_line_returns_none(parser):
    raw_line = (
        "Aug 29 18:50:00 server CRON[555]: "
        "(root) CMD (run-parts /etc/cron.hourly)"
    )

    assert parser.parse_line(raw_line) is None


def test_malformed_login_without_username_returns_none(parser):
    raw_line = (
        "Aug 29 18:42:13 server sshd[1234]: "
        "Failed password for from 192.168.1.50"
    )

    assert parser.parse_line(raw_line) is None


def test_invalid_ip_returns_none(parser):
    raw_line = (
        "Aug 29 18:42:13 server sshd[1234]: "
        "Failed password for admin from 999.999.999.999 "
        "port 54321 ssh2"
    )

    assert parser.parse_line(raw_line) is None
