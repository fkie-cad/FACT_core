import pytest

from ..internal.rulebook import (
    RELATIONS,
    MetaRule,
    SingleRule,
    SoftwareRule,
    SubPathRule,
    _evaluate_meta_rule,
    _evaluate_single_rule,
    _evaluate_sub_path_rule,
    _get_dotted_path_from_dictionary,
    _get_value,
    evaluate,
)

# FixMe: result structure changed when IP&URI plugin was ported to new base class
IPS = {
    'ip_and_uri_finder': {
        'summary': ['1', '2', '3', '4', 'a', 'b', 'c'],
        'timestamp': 1000000,
        'ip_v4': [
            {'address': '1', 'location': [12, 13]},
            {'address': '2', 'location': [22, 12]},
            {'address': '3', 'location': [-1, 6]},
            {'address': '4', 'location': [81, 42]},
        ],
        'uri': ['a', 'b', 'c'],
    }
}

RULE_MATCH = SingleRule(value_path=['ip_and_uri_finder.ip_v4', 'address'], relation='equals', comparison='2')
RULE_NO_MATCH = SingleRule(value_path=['ip_and_uri_finder.ip_v4', 'address'], relation='equals', comparison='5')


def test_get_dotted_path_from_dictionary():
    abc = {'a': {'b': {'c': 5}}}
    assert _get_dotted_path_from_dictionary(abc, 'a') == {'b': {'c': 5}}
    assert _get_dotted_path_from_dictionary(abc, 'a.b') == {'c': 5}
    assert _get_dotted_path_from_dictionary(abc, 'a.b.c') == 5


def test_get_value():
    abc = {'a': {'b': [1, 2, 3]}}
    assert _get_value(abc, ['a.b']) == [1, 2, 3]

    abc = {'a': {'b': [{'c': 5}]}}
    assert _get_value(abc, ['a.b', 'c']) == [
        5,
    ]

    abc = {'a': {'b': [{'c': {'d': 1}}, {'c': {'d': 2}}, {'c': {'d': 3}}]}}
    assert _get_value(abc, ['a.b', 'c.d']) == [1, 2, 3]

    assert _get_value(IPS, ['ip_and_uri_finder.ip_v4', 'address']) == ['1', '2', '3', '4']


@pytest.mark.parametrize('relation', list(RELATIONS.keys()))
def test_all_rules_are_booleans(relation):
    if relation not in ['in', 'reverse_in', 'intersection']:
        assert RELATIONS[relation](1, 2) in [True, False]

    assert RELATIONS[relation]('12', '5') in [True, False]


@pytest.mark.parametrize(
    'relation_value_good_bad',
    [
        ('equals', 5, 5, 4),
        ('is', '42', '42', 42),
        ('gt', 100, 99, 101),
        ('lt', 100, 101, 99),
        ('in', '42', 'i like 42', 'more a 1337 guy'),
        ('reverse_in', [1, 3], 3, 2),
        ('intersection', [1, 2, 3], [2, 3], [4, 5]),  # 'exists' can not be tested this way since its never false
    ],
)
def test_apply_relation(relation_value_good_bad):
    relation, value, good, bad = relation_value_good_bad
    assert RELATIONS[relation](value, good)
    assert not RELATIONS[relation](value, bad)


def test_evaluate_single_rule():
    assert _evaluate_single_rule(IPS, RULE_MATCH)
    assert not _evaluate_single_rule(IPS, RULE_NO_MATCH)


def test_evaluate_meta_rule():
    meta_match = MetaRule(rules=[RULE_MATCH, RULE_NO_MATCH], relation=any)
    meta_no_match = MetaRule(rules=[RULE_MATCH, RULE_NO_MATCH], relation=all)

    assert _evaluate_meta_rule(IPS, meta_match)
    assert not _evaluate_meta_rule(IPS, meta_no_match)


def test_evaluate_base_rule():
    rule_address_match = SingleRule(value_path=['address'], relation='equals', comparison='2')
    rule_location_match = SingleRule(value_path=['location'], relation='equals', comparison=[22, 12])
    rule_location_no_match = SingleRule(value_path=['location'], relation='equals', comparison=[22, 10])

    meta_match = MetaRule(rules=[rule_address_match, rule_location_match], relation=all)
    meta_no_match = MetaRule(rules=[rule_address_match, rule_location_no_match], relation=all)

    sub_path_match = SubPathRule(base_path=['ip_and_uri_finder.ip_v4'], meta_rule=meta_match)
    sub_path_no_match = SubPathRule(base_path=['ip_and_uri_finder.ip_v4'], meta_rule=meta_no_match)

    assert _evaluate_sub_path_rule(IPS, sub_path_match)
    assert not _evaluate_sub_path_rule(IPS, sub_path_no_match)


def test_software_rule():
    rule = SoftwareRule(software_name='foo', affected_versions={'v1.2.2', 'v1.2.3'})
    processed_analysis_match = {
        'software_components': {
            'software_components': [
                {'name': 'foo', 'versions': ['v1.2.2']},
            ]
        }
    }
    processed_analysis_no_match = {
        'software_components': {
            'software_components': [
                {'name': 'foo', 'versions': ['v1.2.1', 'v1.2.4']},
                {'name': 'bar', 'versions': ['v1.2.2']},
            ]
        }
    }

    assert rule.evaluate(processed_analysis_match) is True
    assert rule.evaluate(processed_analysis_no_match) is False


def test_evaluate_bad_type():
    with pytest.raises(TypeError):
        evaluate({}, object())
