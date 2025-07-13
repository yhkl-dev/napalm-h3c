from unittest.mock import MagicMock

import pytest

from napalm_h3c_comware.comware import ComwareDriver


@pytest.fixture
def device():
    """Fixture that returns an instance of your device class"""
    dev = ComwareDriver(
        "127.0.0.1",
        "test",
        "test",
        timeout=200,
        optional_args={"read_output_override": 300, "fast_cli": False, "conn_timeout": 150, "global_delay_factor": 30},
    )
    dev._get_structured_output = MagicMock()
    return dev
