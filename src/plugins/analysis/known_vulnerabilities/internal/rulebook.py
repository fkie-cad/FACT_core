from copy import deepcopy

RELATIONS = {
    'equals': lambda x, y: x == y,
    'is': lambda x, y: x is y,
    'gt': lambda x, y: x > y,
    'lt': lambda x, y: x < y,
    'in': lambda x, y: x in y,
    'reverse_in': lambda x, y: y in x
}


def get_value(analysis, value_path):
    path_copy = deepcopy(value_path)
    part = path_copy.pop(0)
    value = get_dotted_path_from_dictionary(analysis, part)
    if isinstance(value, list) and path_copy:
        return [get_value(item, path_copy) for item in value]
    elif isinstance(value, list):
        return [item for item in value]
    return value


def get_dotted_path_from_dictionary(dictionary, dotted_path):
    if not isinstance(dictionary, dict):
        raise ValueError('path {} can only be extracted from dict - not {}'.format(dotted_path, type(dictionary)))
    if '.' not in dotted_path:
        return dictionary[dotted_path]
    else:
        split_path = dotted_path.split('.')
        return get_dotted_path_from_dictionary(dictionary[split_path[0]], '.'.join(split_path[1:]))


class Rule:
    def __init__(self, value_path, relation, comparison):
        assert isinstance(value_path, list), 'value_path must be list of dot seperated access strings'
        self.value_path = value_path
        assert relation in RELATIONS, 'relation must be one of {}'.format(list(RELATIONS.keys()))
        self.relation = relation
        self.comparison = comparison


class MetaRule:
    def __init__(self, rules, relation):
        assert relation in [any, all], 'only any or all are allowed in MetaRule'
        self.relation = relation
        assert all(isinstance(rule, Rule) for rule in rules), 'all rules in MetaRule must be of type Rule'
        self.rules = rules


def evaluate_rule(rule, analysis):
    if isinstance(rule, MetaRule):
        return rule.relation(evaluate_rule(partial_rule, analysis) for partial_rule in rule.rules)

    values = get_value(analysis, rule.value_path)

    if not isinstance(values, list):
        return apply_relation(rule.relation, values, rule.comparison)

    return any(apply_relation(rule.relation, value, rule.comparison) for value in values)


def apply_relation(relation, value, comparison):
    return RELATIONS[relation](value, comparison)
