from copy import deepcopy
from compare.PluginBase import CompareBasePlugin
from helperFunctions.compare_sets import intersection_of_list_of_lists, difference_of_lists, difference_of_sets


class ComparePlugin(CompareBasePlugin):
    '''
    Compares Software
    '''

    NAME = 'Software'
    DEPENDENCIES = ['software_components']

    def __init__(self, plugin_administrator, config=None, db_interface=None):
        super().__init__(plugin_administrator, config=config, db_interface=db_interface, plugin_path=__file__)

    def compare_function(self, fo_list):
        """
        This function must be implemented by the plug-in.
        'fo_list' is a list with file_objects including analysis and all summaries
        this function should return a dictionary
        """
        tmp = {}
        tmp['software_in_common'] = self._get_intersection_of_software(fo_list)
        tmp['exclusive_software'] = self._get_exclusive_software(fo_list)
        if len(fo_list) > 2:
            tmp['software_in_more_than_one_but_not_in_all'] = self._get_software_in_more_than_one_but_not_in_all(fo_list, tmp)
        return tmp

    def _get_exclusive_software(self, fo_list):
        result = {}
        for i in range(len(fo_list)):
            tmp_list = deepcopy(fo_list)
            current_element = tmp_list.pop(i)
            result[current_element.uid] = difference_of_lists(self._get_software_list(current_element), self._get_list_of_software_lists(tmp_list))
        result['collapse'] = True
        return result

    def _get_intersection_of_software(self, fo_list):
        intersecting_software = intersection_of_list_of_lists(self._get_list_of_software_lists(fo_list))
        result = {'all': intersecting_software}
        result['collapse'] = True
        return result

    def _get_software_in_more_than_one_but_not_in_all(self, fo_list, result_dict):
        result = {}
        for i in range(len(fo_list)):
            tmp_list = deepcopy(fo_list)
            current_element = tmp_list.pop(i)
            result[current_element.uid] = list(difference_of_sets(set(self._get_software_list(current_element)), [result_dict['software_in_common']['all'], result_dict['exclusive_software'][current_element.uid]]))
        result['collapse'] = True
        return result

    def _get_list_of_software_lists(self, fo_list):
        list_of_software_lists = []
        for item in fo_list:
            list_of_software_lists.append(self._get_software_list(item))
        return list_of_software_lists

    @staticmethod
    def _get_software_list(fo):
        return list(fo.processed_analysis['software_components']['summary'].keys())
