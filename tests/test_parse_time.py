import time

import pytest

from napalm_h3c_comware.utils import helpers
from napalm_h3c_comware.utils.helpers import (
    DAY_SECONDS,
    HOUR_SECONDS,
    SECONDS,
    WEEK_SECONDS,
    YEAR_SECONDS,
    _search,
    parse_time,
    strptime,
)


class TestTimeParser:
    @pytest.mark.parametrize(
        "unit, time_str, expected",
        [
            ("year", "1 year", 1),
            ("week", "2 weeks", 2),
            ("day", "3days", 3),
            ("hour", "24HOURS", 24),
            ("minute", "invalid", 0),
        ],
    )
    def test_search_helper(self, unit: str, time_str: str, expected: int) -> None:
        assert _search(unit, time_str) == expected

    def test_search_with_duplicates(self):
        assert _search("minute", "5 minutes 10 minutes") == 5

    @pytest.mark.parametrize(
        "time_str, expected_seconds",
        [
            (
                "1 year 2 weeks 3 days 4 hours 5 minutes 6 seconds",
                YEAR_SECONDS + 2 * WEEK_SECONDS + 3 * DAY_SECONDS + 4 * HOUR_SECONDS + 5 * SECONDS + 6,
            ),
            ("5 seconds 1 minute", 65),
            ("2 hours 30 seconds", 2 * HOUR_SECONDS + 30),
            ("0 years 0 seconds", 0),
        ],
    )
    def test_valid_time_strings(self, time_str: str, expected_seconds: int):
        assert parse_time(time_str) == expected_seconds

    def test_empty_string(self):
        assert parse_time("") == 0

    def test_whitespace_string(self):
        assert parse_time("   ") == 0

    def test_strptime_uses_local_time_conversion(self, monkeypatch):
        expected_time_array = time.strptime("2024-01-02 03:04:05", "%Y-%m-%d %H:%M:%S")
        calls = {"value": None}

        monkeypatch.setattr(helpers.time, "strptime", lambda *_args, **_kwargs: expected_time_array)

        def fake_mktime(time_array):
            calls["value"] = time_array
            return 1704135845.0

        monkeypatch.setattr(helpers.time, "mktime", fake_mktime)

        assert strptime("2024-01-02 03:04:05") == 1704135845.0
        assert calls["value"] == expected_time_array
