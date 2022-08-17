import pytest

from plugins.analysis.known_vulnerabilities.internal.rulebook import BadRuleError, SingleRule, Vulnerability

DUMMY_RULE = SingleRule(['file_type'], 'is', 'application/octet-stream')


@pytest.mark.parametrize('reliability', ['no_integer', None, '200'])
def test_bad_reliability(reliability):
    with pytest.raises(BadRuleError):
        Vulnerability(
            description='', score='high', reliability=reliability, short_name='name', rule=DUMMY_RULE, link=None,
        )


@pytest.mark.parametrize('score', ['higher', None, 50])
def test_bad_score(score):
    with pytest.raises(BadRuleError):
        Vulnerability(description='', score=score, reliability='50', short_name='name', rule=DUMMY_RULE, link=None)


@pytest.mark.parametrize('description', [None, 12, dict(prefix='any')])
def test_bad_description(description):
    with pytest.raises(BadRuleError):
        Vulnerability(
            description=description, score='high', reliability='50', short_name='name', rule=DUMMY_RULE, link=None,
        )


@pytest.mark.parametrize('name', [None, 12, dict()])
def test_bad_name(name):
    with pytest.raises(BadRuleError):
        Vulnerability(description='', score='high', reliability='50', short_name=name, rule=DUMMY_RULE, link=None)


@pytest.mark.parametrize('rule', [None, 12, '', dict(a=2)])
def test_bad_rule(rule):
    with pytest.raises(BadRuleError):
        Vulnerability(description='', score='high', reliability='50', short_name='name', rule=rule, link=None)


@pytest.mark.parametrize('link', [12, dict(a=2)])
def test_bad_link(link):
    with pytest.raises(BadRuleError):
        Vulnerability(description='', score='high', reliability='50', short_name='name', rule=DUMMY_RULE, link=link)


def test_dummy_vulnerability():
    vulnerability = Vulnerability(
        description='',
        score='high',
        reliability='50',
        short_name='dummy bug',
        rule=DUMMY_RULE,
        link='http://dummy.gov',
    )
    meta_data = vulnerability.get_dict()
    assert all(key in meta_data for key in ['score', 'description', 'reliability', 'link', 'short_name'])
    assert meta_data['short_name'] == 'dummy bug'
