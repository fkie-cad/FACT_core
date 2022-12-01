import unittest

from ..internal.string_eval import (
    _add_case_ratio_score,
    _add_dictionary_score,
    _add_format_string_score,
    _add_html_score,
    _add_length_score,
    _add_mail_adress_score,
    _add_parameter_score,
    _add_path_score,
    _add_possible_version_number_score,
    _add_possible_year_score,
    _add_quad_characters_score,
    _add_rare_special_character_score,
    _add_special_character_ratio_score,
    _add_underscore_or_period_at_beginning_score,
    _score,
    eval_strings,
)


class TestStringEval(unittest.TestCase):
    def test_eval_strings(self):
        input_data = ['this string is useful', 'garbage n$%Schtz', '/an/interesting/directory']
        result = eval_strings(input_data)
        self.assertEqual(
            result, ['/an/interesting/directory', 'this string is useful', 'garbage n$%Schtz'], 'Fehler beim bewerten'
        )

    def test_add_mail_adress_score(self):
        input_data_true = 'here is my@mail.com'
        input_data_false = 'here is nothing'
        result_true = _add_mail_adress_score(input_data_true, 0)
        result_false = _add_mail_adress_score(input_data_false, 0)
        assert result_true > 0, 'Mail false-negative'
        assert result_false == 0, 'Mail false-positive'

    def test_add_parameter_score(self):
        input_true = '-p p does something'
        input_true2 = '--help this also does something'
        input_false = 'this is not a startup option'
        result_true = _add_parameter_score(input_true, 0)
        result_true2 = _add_parameter_score(input_true2, 0)
        result_false = _add_parameter_score(input_false, 0)
        assert result_true > 0, 'Parameter not detected'
        assert result_true2 > 0, 'Parameter not detected'
        assert result_false == 0, 'Parameter wrongly detected'

    def test_add_html_score(self):
        input_true = '<body>'
        input_true2 = '</body>'
        input_false = '<head'
        result_true = _add_html_score(input_true, 0)
        result_true2 = _add_html_score(input_true2, 0)
        result_false = _add_html_score(input_false, 0)
        assert result_true > 0, 'html not detected'
        assert result_true2 > 0, 'html not detected'
        assert result_false == 0, 'html wrongly detected'

    def test_add_case_ratio_score(self):
        input_true = 'This is normal text'
        input_false = 'THIS iS WeiRD'
        result_true = _add_case_ratio_score(input_true, 0)
        result_false = _add_case_ratio_score(input_false, 0)
        assert result_true > 0, 'case ratio wrongly detected'
        assert result_false < 0, 'case ratio wrongly detected'

    def test_add_dictionary_score(self):
        input_true = 'version'
        input_true2 = 'http'
        input_false = 'wheelchair'
        result_true = _add_dictionary_score(input_true, 0)
        result_true2 = _add_dictionary_score(input_true2, 0)
        result_false = _add_dictionary_score(input_false, 0)
        assert result_true > 0, 'dict word not detected'
        assert result_true2 > 0, 'dict word not detected'
        assert result_false == 0, 'dict word wrongly detected'

    def test_add_format_string_score(self):
        input_true = 'contains %s'
        input_true2 = '%lf'
        input_false = 'nothing here'
        result_true = _add_format_string_score(input_true, 0)
        result_true2 = _add_format_string_score(input_true2, 0)
        result_false = _add_format_string_score(input_false, 0)
        assert result_true < 0, 'Parameter not detected'
        assert result_true2 < 0, 'Parameter not detected'
        assert result_false == 0, 'Parameter wrongly detected'

    def test_add_length_score(self):
        input_data = 'four'
        result = _add_length_score(input_data, 0)
        assert result == 2, 'Parameter not detected'

    def test_add_path_score(self):
        input_true = 'path: /home/user'
        input_false = 'no path'
        result_true = _add_path_score(input_true, 0)
        result_false = _add_path_score(input_false, 0)
        assert result_true > 0, 'Path not detected'
        assert result_false == 0, 'Path wrongly detected'

    def test_add_possible_version_number_score(self):
        input_true = '1.4.4'
        input_false = 'blabla5'
        result_true = _add_possible_version_number_score(input_true, 0)
        result_false = _add_possible_version_number_score(input_false, 0)
        assert result_true > 0, 'version not detected'
        assert result_false == 0, 'version wrongly detected'

    def test_add_possible_year_score(self):
        input_true = 'this year is 2017'
        input_false = '1089 is to early to be of any use'
        result_true = _add_possible_year_score(input_true, 0)
        result_false = _add_possible_year_score(input_false, 0)
        assert result_true > 0, 'year not detected'
        assert result_false == 0, 'year wrongly detected'

    def test_add_quad_characters_score(self):
        input_true = 'qqqq'
        input_false = 'www'
        result_true = _add_quad_characters_score(input_true, 0)
        result_false = _add_quad_characters_score(input_false, 0)
        assert result_true < 0, 'qcharacter not detected'
        assert result_false == 0, 'qcharacter wrongly detected'

    def test_add_rare_special_character_score(self):
        input_true = '^ is rare'
        input_false = '. is not rare'
        result_true = _add_rare_special_character_score(input_true, 0)
        result_false = _add_rare_special_character_score(input_false, 0)
        assert result_true < 0, 'rare character not detected'
        assert result_false == 0, 'rare character wrongly detected'

    def test_add_special_character_ratio_score(self):
        input_true = '$$$$ab&%!'
        input_false = 'normal text!'
        result_true = _add_special_character_ratio_score(input_true, 0)
        result_false = _add_special_character_ratio_score(input_false, 0)
        assert result_true < 0, 'special normal ratio fail'
        assert result_false > 0, 'special to normal ratio fail2'

    def test_add_underscore_or_period_at_beginning_score(self):
        input_true = '_hello'
        input_true2 = '__magic'
        input_true3 = '.gitgud'
        result_true = _add_underscore_or_period_at_beginning_score(input_true, 0)
        result_true2 = _add_underscore_or_period_at_beginning_score(input_true2, 0)
        result_true3 = _add_underscore_or_period_at_beginning_score(input_true3, 0)
        assert result_true < 0, 'underscore or period not detected'
        assert result_true2 < 0, 'underscore or period not detected'
        assert result_true3 < 0, 'underscore or period not detected'

    def test_score(self):
        input_data = 'score me pls'
        result = _score(input_data)
        assert result[1] > 0, 'score should be above 0!'
