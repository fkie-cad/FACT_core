from copy import deepcopy

RELATIONS = {
    'equals': lambda x, y: x == y,
    'is': lambda x, y: x is y,
    'gt': lambda x, y: x > y,
    'lt': lambda x, y: x < y,
    'in': lambda x, y: x in y,
    'reverse_in': lambda x, y: y in x
}


class SingleRule:
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
        assert all(isinstance(rule, SingleRule) for rule in rules), 'all rules in MetaRule must be of type Rule'
        self.rules = rules


class SubPathRule:
    def __init__(self, base_path, meta_rule):
        assert isinstance(base_path, list), 'base_path must be list of dot seperated access strings'
        self.base_path = base_path
        assert isinstance(meta_rule, MetaRule), 'rules must be a MetaRule'
        self.meta_rule = meta_rule


def evaluate(analysis, rule):
    if isinstance(rule, MetaRule):
        result = _evaluate_meta_rule(analysis, rule)
    elif isinstance(rule, SingleRule):
        result = _evaluate_single_rule(analysis, rule)
    elif isinstance(rule, SubPathRule):
        result = _evaluate_sub_path_rule(analysis, rule)
    else:
        raise TypeError('rule must be of one in types [SingleRule, MetaRule, SubPathRule]')
    return result


def _evaluate_single_rule(analysis, rule):
    values = _get_value(analysis, rule.value_path)
    if not isinstance(values, list) or isinstance(rule.comparison, list):
        return _apply_relation(rule.relation, values, rule.comparison)
    return any(_apply_relation(rule.relation, value, rule.comparison) for value in values)


def _evaluate_meta_rule(analysis, rule):
    return rule.relation(evaluate(analysis, partial_rule) for partial_rule in rule.rules)


def _evaluate_sub_path_rule(analysis, rule):
    values = _get_value(analysis, rule.base_path)
    if not isinstance(values, list):
        return _evaluate_meta_rule(values, rule.meta_rule)
    return any(_evaluate_meta_rule(value, rule.meta_rule) for value in values)


def _apply_relation(relation, value, comparison):
    return RELATIONS[relation](value, comparison)


def _get_value(analysis, value_path):
    path_copy = deepcopy(value_path)
    part = path_copy.pop(0)
    value = _get_dotted_path_from_dictionary(analysis, part)
    if isinstance(value, list) and path_copy:
        return [_get_value(item, path_copy) for item in value]
    elif isinstance(value, list):
        return [item for item in value]
    return value


def _get_dotted_path_from_dictionary(dictionary, dotted_path):
    if not isinstance(dictionary, dict):
        raise ValueError('path {} can only be extracted from dict - not {}'.format(dotted_path, type(dictionary)))
    if '.' not in dotted_path:
        return dictionary[dotted_path]
    else:
        split_path = dotted_path.split('.')
        return _get_dotted_path_from_dictionary(dictionary[split_path[0]], '.'.join(split_path[1:]))
