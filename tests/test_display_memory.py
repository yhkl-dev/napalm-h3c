import pytest
from textfsm import TextFSM


@pytest.fixture
def memory_template():
    with open("napalm_h3c_comware/utils/textfsm_templates/display_memory.tpl") as f:
        return TextFSM(f)


@pytest.fixture
def memory_normal_output():
    return """
Memory statistics are measured in KB:
Slot 1:
             Total      Used      Free    Shared   Buffers    Cached   FreeRatio
Mem:        506408    362496    143912         0      1376    123024       30.7%
-/+ Buffers/Cache:    238096    268312
Swap:            0         0         0

Slot 2:
             Total      Used      Free    Shared   Buffers    Cached   FreeRatio
Mem:        506408    330976    175432         0      1376    112976       35.0%
-/+ Buffers/Cache:    216624    289784
Swap:            0         0         0

    """


def test_memory_parsing(memory_template, memory_normal_output):
    result = memory_template.ParseText(memory_normal_output)

    assert len(result) == 2
    record = result[0]
    assert record == ["", "1", "506408", "362496", "143912", "0", "1376", "123024", "30.7"]


def test_incomplete_data(memory_template):
    """测试缺失关键字段"""
    output = """
Memory statistics are measured in KB:
Slot 1:
             Total      Used      Free    Shared   Buffers    Cached
Mem:        506408    362496    143912         0      1376    123024
-/+ Buffers/Cache:    238096    268312
Swap:            0         0         0
    """
    result = memory_template.ParseText(output)
    print(result)
    assert result[0][1] == "1"
    assert result[0][4] == ""
