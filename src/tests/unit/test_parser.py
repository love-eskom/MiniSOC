from minisoc.models.event import EventSchema
from minisoc.parsers.base import BaseParser
import pytest
from datetime import datetime

def test_base_parser():
    with pytest.raises(TypeError):
        base = BaseParser()

def test_abstract():
    class IncompleteParser(BaseParser):
        pass
    
    with pytest.raises(TypeError):
        IncompleteParser()
        

def test_concrete_parser():
    class TestParser(BaseParser):
        def parse_line(self, raw_line:str) -> EventSchema:
            return EventSchema(timestamp= datetime.now(), event_type="Brute")

    parser = TestParser()
    event = parser.parse_line("some raw log")
    
    assert isinstance(event, EventSchema)
    assert event.event_type == "Brute"

