from copy import deepcopy

RELATIONS = {
    'exists': lambda x, y: True,
    'equals': lambda x, y: x == y,
    'is': lambda x, y: x is y,
    'gt': lambda x, y: x > y,
    'lt': lambda x, y: x < y,
    'in': lambda x, y: x in y,
    'reverse_in': lambda x, y: y in x,
    'intersection': lambda x, y: bool(set(x).intersection(set(y)))
}


class BadRuleError(ValueError):
    pass


class Vulnerability:
    def __init__(self, rule, description, reliability, score, link, short_name):
        try:
            self.reliability = str(int(reliability))
            self.score = score
            self.description = description
            self.rule = rule
            self.link = link
            self.short_name = short_name

            self._make_type_assertions(link, rule)
        except (ValueError, TypeError) as exception:
            raise BadRuleError(str(exception))

    def _make_type_assertions(self, link, rule):
        for type_assertion, error_message in [
            (int(self.reliability) in range(0, 101), 'reliability must be between 0 and 100'),
            (self.score in ['low', 'medium', 'high'], 'score has to be one of low, medium or high'),
            (isinstance(self.description, str), 'description must be a string'),
            (isinstance(self.rule, (SingleRule, MetaRule, SubPathRule)), 'rule must be of type in [SingleRule, MetaRule, SubPathRule]. Has type {}'.format(type(rule))),
            (isinstance(self.link, str) or not link, 'if link is set it has to be a string'),
            (isinstance(self.short_name, str), 'short_name has to be a string')
        ]:
            if not type_assertion:
                raise ValueError(error_message)

    def get_dict(self):
        return dict(description=self.description, score=self.score, reliability=self.reliability, link=self.link, short_name=self.short_name)


class SingleRule:
    def __init__(self, value_path, relation, comparison):
        for assertion, error_message in [
            (isinstance(value_path, list), 'value_path must be list of dot seperated access strings'),
            (relation in RELATIONS, 'relation must be one of {}'.format(list(RELATIONS.keys())))
        ]:
            if not assertion:
                raise BadRuleError(error_message)

        self.value_path = value_path
        self.relation = relation
        self.comparison = comparison


class MetaRule:
    def __init__(self, rules, relation):
        for assertion, error_message in [
            (relation in [any, all], 'only any or all are allowed in MetaRule'),
            (all(isinstance(rule, SingleRule) for rule in rules), 'all rules in MetaRule must be of type Rule')
        ]:
            if not assertion:
                raise BadRuleError(error_message)

        self.relation = relation
        self.rules = rules


class SubPathRule:
    def __init__(self, base_path, meta_rule):
        for assertion, error_message in [
            (isinstance(base_path, list), 'base_path must be list of dot seperated access strings'),
            (isinstance(meta_rule, MetaRule), 'rules must be a MetaRule')
        ]:
            if not assertion:
                raise BadRuleError(error_message)

        self.base_path = base_path
        self.meta_rule = meta_rule


def evaluate(analysis, rule):
    try:
        if isinstance(rule, MetaRule):
            result = _evaluate_meta_rule(analysis, rule)
        elif isinstance(rule, SingleRule):
            result = _evaluate_single_rule(analysis, rule)
        elif isinstance(rule, SubPathRule):
            result = _evaluate_sub_path_rule(analysis, rule)
        else:
            raise TypeError('rule must be of one in types [SingleRule, MetaRule, SubPathRule]')
        return result
    except KeyError:  # expected behavior as long as this does not have all other plugins as dependency
        return False


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
    result = RELATIONS[relation](value, comparison)
    return result


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


def vulnerabilities():
    heartbleed_rule = SingleRule(
        value_path=['software_components.OpenSSL.meta.version'],
        relation='intersection',
        comparison=['1.0.1{}'.format(minor) for minor in 'abcde']
    )
    heartbleed_vulnerability = Vulnerability(
        rule=heartbleed_rule,
        short_name='Heartbleed',
        description='The SSL Hearbleed bug allowing buffer overread',
        score='high',
        reliability='90',
        link='https://nvd.nist.gov/vuln/detail/CVE-2014-0160'
    )

    netgear_cgi_rule = SingleRule(
        value_path=['file_hashes.sha256'],
        relation='equals',
        comparison='7579d10e812905e134cf91ad8eef7b08f87f6f8c8e004ebefa441781fea0ec4a'
    )
    netgear_cgi_vulnerability = Vulnerability(
        rule=netgear_cgi_rule,
        short_name='Netgear_CGI',
        description='Netgear httpd vulnerable to "/cgi-bin/<shell command>" bug',
        score='medium',
        reliability='100',
        link='https://nvd.nist.gov/vuln/detail/CVE-2016-6277'
    )

    return [heartbleed_vulnerability, netgear_cgi_vulnerability]
