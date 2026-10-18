## 1. `linux_auth.py` — The parser

**Purpose:** Convert raw Linux SSH authentication logs into standardized `EventSchema` objects.

### Processing flow

`Raw log → Regex match → Extract fields → Validate → EventSchema`

- `class LinuxAuthParser(BaseParser)`: inherits the shared parser contract.
    
- `re.compile(...)`: creates a reusable regex pattern.
    
- `(?P<user>...)`: named capture group for extracting the username.
    
- `match.groupdict()`: returns captured fields in a dictionary.
    
- `datetime.strptime(...)`: converts timestamp text into a `datetime`.
    
- `ipaddress.ip_address(...)`: validates the source IP.
    
- `return None`: discards unrelated or unusable log entries.
    

### Regex syntax

|Syntax|Meaning|
|---|---|
|`\d+`|One or more digits|
|`\s+`|One or more whitespace characters|
|`\S+`|One or more non-whitespace characters|
|`[...]`|Character class|
|`(...)`|Capture/group pattern|
|`(?P<name>...)`|Named capture group|
|`|`|OR — match either alternative|
|`\[` and `\]`|Match literal square brackets|

**Important:** Regex finds matching text; it doesn't automatically prove that the extracted data is valid. That's why IP and timestamp validation are separate steps.

## 2. `test_linux_auth_parser.py` — The tests

**Purpose:** Verify the parser's expected behaviour without requiring real log files or a running server.

- `@pytest.fixture`: creates a reusable parser for tests.
    
- `def test_...`: defines an individual test.
    
- `assert`: checks whether the result matches expectations.
    
- `isinstance(event, EventSchema)`: verifies the returned object's type.
    
- `is None`: verifies that an unusable line is discarded.
    

### What we test

1. Failed SSH login → `status="Failed"`.
    
2. Successful SSH login → `status="Success"`.
    
3. Invalid username attempt → captures the attempted username.
    
4. Unrelated log → returns `None`.
    
5. Missing username → returns `None`.
    
6. Invalid IP → returns `None`.
    