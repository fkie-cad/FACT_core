import re  # noqa: EXE002


def eval_strings(str_list):
    scored_list = [_score(string) for string in str_list]
    scored_list.sort(key=lambda element: element[1], reverse=True)
    return [score_tupel[0] for score_tupel in scored_list]


def _score(string):
    score = 0
    score = _add_length_score(string, score)
    score = _add_rare_special_character_score(string, score)
    score = _add_special_character_ratio_score(string, score)
    score = _add_case_ratio_score(string, score)
    score = _add_quad_characters_score(string, score)
    score = _add_dictionary_score(string, score)
    score = _add_path_score(string, score)
    score = _add_possible_year_score(string, score)
    score = _add_possible_version_number_score(string, score)
    score = _add_format_string_score(string, score)
    score = _add_mail_adress_score(string, score)
    score = _add_underscore_or_period_at_beginning_score(string, score)
    score = _add_parameter_score(string, score)
    score = _add_html_score(string, score)
    return string, score


def _add_length_score(string, score):
    return score + len(string) / 2


def _add_rare_special_character_score(string, score):
    rare_characters = ['^', '°', '§', '´', '`', '{', '}']
    return score - 15 * len([character for character in rare_characters if character in string])


def _add_special_character_ratio_score(string, score):
    regex_non_word = r'\W'
    regex_word = r'[a-zA-Z]'
    matches_non_word = re.finditer(regex_non_word, string)
    matches_word = re.finditer(regex_word, string)
    match_num_non_word = len(list(matches_non_word))
    match_num_word = len(list(matches_word))
    score += _ratio_word_non_word_helper(match_num_word, match_num_non_word)
    return score


def _ratio_word_non_word_helper(num_word, num_non_word):
    ratio = num_word if num_non_word == 0 else num_word / num_non_word
    return 15 if ratio >= 2 else -15  # noqa: PLR2004


def _add_case_ratio_score(string, score):
    regex_lower = r'[a-z]'
    regex_capital = r'[A-Z]'
    matches_lower_case = re.finditer(regex_lower, string)
    matches_capital = re.finditer(regex_capital, string)
    match_num_lower = len(list(matches_lower_case))
    match_num_capital = len(list(matches_capital))
    score += _case_ratio_helper(match_num_lower, match_num_capital)
    return score


def _case_ratio_helper(num_lower, num_capital):
    # all caps
    if num_lower == 0 and num_capital >= 6:  # noqa: PLR2004
        return num_capital / 2
    case_ratio = num_lower if num_capital == 0 else num_lower / num_capital
    return 10 if case_ratio > 1 else -10


def _add_quad_characters_score(string, score):
    matches = re.finditer(r'(\S)\1\1\1', string)
    return score - 25 * len(list(matches))


def _add_dictionary_score(string, score):
    dictionary = ['version', 'v.', 'http', 'ftp', 'usage', 'Usage', 'ssh', 'SSH', 'password', 'Version']
    return score + 30 * len([word for word in dictionary if word in string])


def _add_possible_year_score(string, score):
    regex = r'([1][9]\d\d)|([2][0]\d\d)'
    matches = re.search(regex, string)
    return score + 20 if matches else score


def _add_path_score(string, score):
    regex = r'(\/[\w-]+)+(.[a-zA-Z]+)'
    matches = re.search(regex, string)
    return score + 100 if matches else score


def _add_possible_version_number_score(string, score):
    regex = r'\d+\.(\d+\.?)+'
    matches = re.search(regex, string)
    return score + 35 if matches else score


def _add_format_string_score(string, score):
    regex = r'%s|%lu|%u|%lf|%f|%i|%d'
    matches = re.finditer(regex, string)
    return score - 15 * len(list(matches))


def _add_mail_adress_score(string, score):
    regex = r'(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))'  # noqa: E501
    match = re.search(regex, string)
    return score + 150 if match else score


def _add_underscore_or_period_at_beginning_score(string, score):
    match = re.search(r'(^_+)|^\.', string)
    return score - 25 if match else score


def _add_parameter_score(string, score):
    match = re.search(r'^\s*-{1,2}', string)
    return score + 35 if match and len(string) > 6 else score  # noqa: PLR2004


def _add_html_score(string, score):
    regex = r'</?[^\\\(\)$\[\]\§\.\,\?<>;|!]+>'
    match = re.search(regex, string)
    return score + 15 if match else score
