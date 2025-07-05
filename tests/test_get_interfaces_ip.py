from typing import Dict

import pytest


class TestGetInterfacesIP:
    """Test suite for get_interfaces_ip() method"""

    @pytest.mark.parametrize(
        "input_data,expected",
        [
            # Test case 1: Normal case with multiple interfaces
            (
                [
                    {"interface": "GigabitEthernet1/0/1", "ip_address": ["192.168.1.1/24", "10.0.0.1/30"]},
                    {"interface": "Loopback0", "ip_address": ["10.1.1.1/32"]},
                    {"interface": "Vlan100", "ip_address": []},
                ],
                {
                    "GigabitEthernet1/0/1": {
                        "ipv4": {"192.168.1.1": {"prefix_length": 24}, "10.0.0.1": {"prefix_length": 30}}
                    },
                    "Loopback0": {"ipv4": {"10.1.1.1": {"prefix_length": 32}}},
                },
            ),
            # Test case 2: Empty IP list should be skipped
            ([{"interface": "Vlan100", "ip_address": []}], {}),
            # Test case 3: Malformed IP addresses should be skipped
            (
                [
                    {"interface": "GigabitEthernet1/0/1", "ip_address": ["192.168.1.1/24", "invalid"]},
                    {"interface": "GigabitEthernet1/0/2", "ip_address": ["missing_prefix"]},
                ],
                {"GigabitEthernet1/0/1": {"ipv4": {"192.168.1.1": {"prefix_length": 24}}}},
            ),
            # Test case 4: Missing interface key
            ([{"wrong_key": "value"}], {}),
            # Test case 5: Empty input
            ([], {}),
        ],
    )
    def test_various_cases(self, device, input_data, expected):
        """Test multiple scenarios with parametrized inputs"""
        device._get_structured_output.return_value = input_data
        result = device.get_interfaces_ip()
        assert result == expected

    def test_command_execution_failure(self, device):
        """Test behavior when command execution fails"""
        device._get_structured_output.side_effect = Exception("Command failed")
        with pytest.raises(RuntimeError, match="Failed to execute 'display ip interface'"):
            device.get_interfaces_ip()

    def test_return_type(self, device):
        """Verify the return type matches the type hint"""
        device._get_structured_output.return_value = [{"interface": "Loopback0", "ip_address": ["10.1.1.1/32"]}]
        result = device.get_interfaces_ip()
        assert isinstance(result, Dict)
        assert all(isinstance(key, str) for key in result.keys())
