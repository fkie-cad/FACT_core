import pytest

from ..internal.rulebook import evaluate_rule, get_value, get_dotted_path_from_dictionary, MetaRule, Rule, RELATIONS

IPS = {
    'ip_and_uri_finder': {
        'summary': ['1', '2', '3', '4', 'a', 'b', 'c'],
        'timestamp': 1000000,
        'ip_v4': [
            {
                'address': '1',
                'location': [12, 13]
            },
            {
                'address': '2',
                'location': [22, 12]
            },
            {
                'address': '3',
                'location': [-1, 6]
            },
            {
                'address': '4',
                'location': [81, 42]
            },
        ],
        'uri': ['a', 'b', 'c']
    }
}


def test_get_dotted_path_from_dictionary():
    abc = {'a': {'b': {'c': 5}}}
    assert get_dotted_path_from_dictionary(abc, 'a') == {'b': {'c': 5}}
    assert get_dotted_path_from_dictionary(abc, 'a.b') == {'c': 5}
    assert get_dotted_path_from_dictionary(abc, 'a.b.c') == 5


def test_get_value():
    abc = {'a': {'b': [1, 2, 3]}}
    assert get_value(abc, ['a.b']) == [1, 2, 3]

    abc = {'a': {'b': [{'c': 5}]}}
    assert get_value(abc, ['a.b', 'c']) == [5, ]

    abc = {'a': {'b': [{'c': {'d': 1}}, {'c': {'d': 2}}, {'c': {'d': 3}}]}}
    assert get_value(abc, ['a.b', 'c.d']) == [1, 2, 3]

    assert get_value(IPS, ['ip_and_uri_finder.ip_v4', 'address']) == ['1', '2', '3', '4']


@pytest.mark.parametrize('relation', list(RELATIONS.keys()))
def test_all_rules_are_booleans(relation):
    if relation not in ['in', 'reverse_in']:
        assert RELATIONS[relation](1, 2) in [True, False]

    assert RELATIONS[relation]('12', '5') in [True, False]


@pytest.mark.parametrize('relation_value_good_bad', [
    ('equals', 5, 5, 4),
    ('is', '42', '42', 42),
    ('gt', 100, 99, 101),
    ('lt', 100, 101, 99),
    ('in', '42', 'i like 42', 'more a 1337 guy'),
    ('reverse_in', [1, 3], 3, 2)
])
def test_apply_relation(relation_value_good_bad):
    relation, value, good, bad = relation_value_good_bad
    assert RELATIONS[relation](value, good)
    assert not RELATIONS[relation](value, bad)


def test_evaluate_rule():
    test_rule_match = Rule(value_path=['ip_and_uri_finder.ip_v4', 'address'], relation='equals', comparison='2')
    test_rule_no_match = Rule(value_path=['ip_and_uri_finder.ip_v4', 'address'], relation='equals', comparison='5')

    assert evaluate_rule(test_rule_match, IPS)
    assert not evaluate_rule(test_rule_no_match, IPS)

    meta_rule_match = MetaRule(rules=[test_rule_match, test_rule_no_match], relation=any)
    meta_rule_no_match = MetaRule(rules=[test_rule_match, test_rule_no_match], relation=all)

    assert evaluate_rule(meta_rule_match, IPS)
    assert not evaluate_rule(meta_rule_no_match, IPS)
