import pytest

from ..internal.lua_linter import LuaLinter

MOCK_RESPONSE = '''/usr/share/nmap/nse_main.lua:88:7-12: (W211) unused variable 'select'
/usr/share/nmap/nse_main.lua:140:11-14 (W431) shadowing upvalue 'type' on line 92
/usr/share/nmap/nse_main.lua:204:9-14: (W421) shadowing definition of variable 'resume' on line 96
/usr/share/nmap/nse_main.lua:285:44-44: (W432) shadowing upvalue argument 'a' on line 284
/usr/share/nmap/nse_main.lua:476:16-21: (W113) accessing undefined variable 'action'
/usr/share/nmap/nse_main.lua:585:11-23: (W412) variable 'script_params' was previously defined as an argument on line 584
/usr/share/nmap/nse_main.lua:646:9-9: (W213) unused loop variable 'i'
/usr/share/nmap/nse_main.lua:726:19-22: (W413) variable 'rule' was previously defined as a loop variable on line 724
/usr/share/nmap/nse_main.lua:881:35-39: (W212) unused argument 'hosts'
/usr/share/nmap/nse_main.lua:1362:9-17: (W411) variable 'runlevels' was previously defined on line 1336
'''


@pytest.fixture(scope='function')
def stub_linter():
    return LuaLinter()


def test_do_analysis(stub_linter, monkeypatch):
    monkeypatch.setattr('plugins.analysis.linter.internal.lua_linter.execute_shell_command', lambda command: MOCK_RESPONSE)
    result = stub_linter.do_analysis('any/path')
    assert result
    assert len(result) == 10
    assert result[0] == {
        'message': 'unused variable \'select\'',
        'line': 88,
        'column': 7,
        'symbol': 'W211'
    }


def test_bad_lines(stub_linter, monkeypatch):
    bad_lines = MOCK_RESPONSE[0:2].replace(':', ' ')
    monkeypatch.setattr('plugins.analysis.linter.internal.lua_linter.execute_shell_command', lambda command: bad_lines)
    result = stub_linter.do_analysis('any/path')
    assert not result


def test_skip_w6xy(stub_linter, monkeypatch):
    w6xy = MOCK_RESPONSE[0:1].replace('W211', 'W631')
    monkeypatch.setattr('plugins.analysis.linter.internal.lua_linter.execute_shell_command', lambda command: w6xy)
    result = stub_linter.do_analysis('any/path')
    assert not result
