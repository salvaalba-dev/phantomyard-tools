import pytest

from phantomdocs.view_agent_journal import _decode, _encode


def test_journal_round_trip():
    assert _decode(_encode(b'{"routes":[]}', "revision")) == (
        b'{"routes":[]}',
        "revision",
    )


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"{}",
        b'{"version":1,"version":1}',
        b'{"version":1,"candidate":"%","revision":"r"}',
    ],
)
def test_corrupt_journal_fails_closed(data):
    with pytest.raises(ValueError):
        _decode(data)
