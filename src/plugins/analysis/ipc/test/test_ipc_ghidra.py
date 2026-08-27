import sys
from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def mock_ghidra_modules(monkeypatch):
    ghidra_mock = MagicMock()
    pcode_op_mock = MagicMock()
    pcode_op_mock.CALL = 1
    pcode_op_mock.CAST = 2
    pcode_op_mock.INT_ADD = 3
    pcode_op_mock.INT_SUB = 4
    pcode_op_mock.INT_MULT = 5
    pcode_op_mock.INT_DIV = 6
    pcode_op_mock.INT_AND = 7
    pcode_op_mock.INT_OR = 8
    pcode_op_mock.INT_XOR = 9
    pcode_op_mock.INT_EQUAL = 10
    pcode_op_mock.INT_NEGATE = 11
    pcode_op_mock.INT_ZEXT = 12
    pcode_op_mock.INT_SEXT = 13
    pcode_op_mock.INT_2COMP = 14
    pcode_op_mock.COPY = 15
    pcode_op_mock.CALLIND = 16
    pcode_op_mock.PIECE = 17
    pcode_op_mock.PTRSUB = 18
    pcode_op_mock.MULTIEQUAL = 19
    pcode_op_mock.INDIRECT = 20
    pcode_op_mock.LOAD = 21
    pcode_op_mock.RETURN = 22

    mock_modules = {
        'ghidra': ghidra_mock,
        'ghidra.program': ghidra_mock.program,
        'ghidra.program.model': ghidra_mock.program.model,
        'ghidra.program.model.pcode': ghidra_mock.program.model.pcode,
        'ghidra.program.model.pcode.PcodeOp': pcode_op_mock,
        'ghidra.program.model.block': ghidra_mock.program.model.block,
        'ghidra.program.model.block.BasicBlockModel': MagicMock(),
        'ghidra.program.model.symbol': ghidra_mock.program.model.symbol,
        'ghidra.program.model.symbol.RefType': MagicMock(),
        'decompile': MagicMock(),
        'ipc_analysis.decompile': MagicMock(),
        'ipc_analysis.helper_functions': MagicMock(),
    }

    for mod_name, mock in mock_modules.items():
        monkeypatch.setitem(sys.modules, mod_name, mock)

    yield

    for key in list(sys.modules):
        if 'ipc_analysis' in key or 'format_strings' in key:
            monkeypatch.delitem(sys.modules, key, raising=False)


@pytest.fixture
def format_strings():
    from plugins.analysis.ipc.docker.ipc_analyzer.resolve_format_strings import format_strings  # noqa: PLC0415

    return format_strings


@pytest.fixture
def helper_functions():
    from plugins.analysis.ipc.docker.ipc_analyzer.ipc_analysis import helper_functions  # noqa: PLC0415

    return helper_functions


class TestFilterRelevantIndices:
    def test_index_out_of_range_handling(self, format_strings):
        """
        Regression test: skip values that exceed arg_values length
        """
        start = 1
        arg_values = [['arg1'], ['arg2']]
        indices = [0, 1, 2, 3]
        # Index 2 and 3 are out of range for arg_values
        format_types = [str, str, str, str]

        result = format_strings.filter_relevant_indices(start, arg_values, indices, format_types)
        assert isinstance(result, list)
        assert len(result) == 1

    def test_empty_arg_values(self, format_strings):
        start = 0
        arg_values = []
        indices = [0, 1]
        format_types = [str, str]

        result = format_strings.filter_relevant_indices(start, arg_values, indices, format_types)

        assert result == []

    def test_negative_start_value(self, format_strings):
        start = -1
        arg_values = [['arg1'], ['arg2'], ['arg3']]
        indices = [0, 1, 2]
        format_types = [str, str, str]

        # With start=-1, indices would be -1, 0, 1
        # -1 is a valid Python index (last element)
        result = format_strings.filter_relevant_indices(start, arg_values, indices, format_types)

        assert isinstance(result, list)


class MockGhidraAnalysis:
    def __init__(self):
        self.current_program = MockCurrentProgram()

        class flat_api:  # noqa: N801
            @staticmethod
            def getFunctionContaining(addr):  # noqa: ARG004, N802
                return None


class MockCurrentProgram:
    def getMetadata(self):  # noqa: N802
        return {'Address Size': 64}


class MockFunc:
    def getAllVariables(self):  # noqa: N802
        return []


class MockVarnode:
    def getDef(self):  # noqa: N802
        return None  # No definition, should normally return empty list


class MockVar:
    pass


@pytest.mark.parametrize('varnode', [None, MockVarnode()])
def test_get_vars_from_varnode(helper_functions, varnode):
    """
    Regression test: When varnode is None, the function should return an empty list
    instead of raising AttributeError: 'NoneType' object has no attribute 'getDef'.
    """
    ghidra_analysis = MockGhidraAnalysis()
    func = MockFunc()

    result = helper_functions.get_vars_from_varnode(ghidra_analysis, func, varnode)

    assert result == []


@pytest.mark.parametrize('varnode', [None, MockVarnode()])
def test_none_source_varnode_handling(helper_functions, varnode):
    class MockSource:
        def getInput(self, index):  # noqa: N802
            if index == 1:
                return varnode
            return None

    sources = [MockSource()]
    result = helper_functions.find_source_value(MockGhidraAnalysis(), MockFunc(), MockVar(), sources)

    assert result is None
