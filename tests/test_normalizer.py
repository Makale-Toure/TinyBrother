from datetime import datetime, timezone
from pathlib import Path

import pytest

from tinybrother.normalizer.windows import NormalizationError, from_xml, parse_timestamp

FIX = Path(__file__).parent / "fixtures"


def load(name: str):
    return from_xml((FIX / name).read_text(encoding="utf-8"))


def test_sysmon_process_creation():
    e = load("sysmon_1.xml")
    assert e.event_id == 1
    assert e.channel == "Microsoft-Windows-Sysmon/Operational"
    assert e.computer == "NEWGATE"
    assert e.record_id == 48213
    assert e.provider == "Microsoft-Windows-Sysmon"
    assert e.fields["Image"].endswith("powershell.exe")
    assert "-enc" in e.fields["CommandLine"]
    assert e.fields["Description"] is None  # empty values become None
    assert e.fields["EventID"] == "1"
    assert e.timestamp == datetime(2026, 10, 4, 10, 15, 42, 123456, tzinfo=timezone.utc)


def test_security_logon():
    e = load("security_4624.xml")
    assert e.event_id == 4624
    assert e.fields["TargetUserName"] == "makyt"
    assert e.fields["LogonType"] == "2"


def test_userdata_is_flattened():
    e = load("security_1102.xml")
    assert e.event_id == 1102
    assert e.fields["SubjectUserName"] == "attacker"


def test_unnamed_data_and_qualifiers():
    e = load("classic_unnamed.xml")
    assert e.event_id == 7036
    assert e.fields["Data_0"] == "Windows Update"
    assert e.fields["Data_1"] == "running"


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("2026-10-04T10:00:00Z", datetime(2026, 10, 4, 10, 0, 0, tzinfo=timezone.utc)),
        ("2026-10-04T10:00:00.5Z", datetime(2026, 10, 4, 10, 0, 0, 500000, tzinfo=timezone.utc)),
        ("2026-10-04T10:00:00.123456789Z",
         datetime(2026, 10, 4, 10, 0, 0, 123456, tzinfo=timezone.utc)),
        ("2026-10-04 10:00:00.000000", datetime(2026, 10, 4, 10, 0, 0, tzinfo=timezone.utc)),
    ],
)
def test_parse_timestamp(raw, expected):
    assert parse_timestamp(raw) == expected


@pytest.mark.parametrize(
    "xml",
    [
        "not xml",
        "<Event><EventData/></Event>",
        "<Event><System><EventID>1</EventID></System></Event>",
    ],
)
def test_invalid_records_raise(xml):
    with pytest.raises(NormalizationError):
        from_xml(xml)
