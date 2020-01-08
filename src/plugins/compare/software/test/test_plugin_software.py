from test.unit.compare.compare_plugin_test_class import ComparePluginTest

from ..code.software import ComparePlugin


class TestComparePluginSoftware(ComparePluginTest):

    # This name must be changed according to the name of plug-in to test
    PLUGIN_NAME = "Software"

    def setup_plugin(self):
        """
        This function must be overwritten by the test instance.
        In most cases it is sufficient to copy this function.
        """
        return ComparePlugin(self, config=self.config)

    def test_get_intersection_of_software(self):
        self.fw_one.processed_analysis['software_components'] = {'summary': {'software a': self.fw_one.uid}}
        self.fw_two.processed_analysis['software_components'] = {'summary': {'software a': self.fw_two.uid, 'software b': self.fw_two.uid}}
        result = self.c_plugin._get_intersection_of_software([self.fw_one, self.fw_two])
        self.assertIsInstance(result, dict, "result is not a dict")
        self.assertIn('all', result, "all field not present")
        self.assertEqual(result['all'], ['software a'], "intersection not correct")
        self.assertTrue(result['collapse'])

    def test_get_exclustive_software(self):
        self.fw_one.processed_analysis['software_components'] = {'summary': {'software a': self.fw_one.uid}}
        self.fw_two.processed_analysis['software_components'] = {'summary': {}}
        result = self.c_plugin._get_exclusive_software([self.fw_one, self.fw_two])
        self.assertIsInstance(result, dict, "result is not a dict")
        self.assertIn(self.fw_one.uid, result, "fw_one entry not found in result")
        self.assertIn(self.fw_two.uid, result, "fw_two entry not found in result")
        self.assertIn('software a', result[self.fw_one.uid], "fw_one not exclusive to one")
        self.assertNotIn('software a', result[self.fw_two.uid], "fw_two in exclusive file of fw one")
        self.assertTrue(result['collapse'])

    def test_get_software_in_more_than_one_but_not_in_all(self):
        self.fw_one.processed_analysis['software_components'] = {'summary': {'software a': self.fw_one.uid}}
        self.fw_two.processed_analysis['software_components'] = {'summary': {'software a': self.fw_two.uid}}
        self.fw_three.processed_analysis['software_components'] = {'summary': {}}
        fo_list = [self.fw_one, self.fw_two, self.fw_three]
        tmp_result_dict = {'software_in_common': {}, 'exclusive_software': {}}
        tmp_result_dict['software_in_common']['all'] = set()
        for i in range(len(fo_list)):
            tmp_result_dict['exclusive_software'][fo_list[i].uid] = {}
        result = self.c_plugin._get_software_in_more_than_one_but_not_in_all(fo_list, tmp_result_dict)
        self.assertIsInstance(result, dict, "result is not a dict")
        self.assertIn('software a', result[self.fw_one.uid], "foo not in result fw one")
        self.assertIn('software a', result[self.fw_two.uid], "foo not in result fw_two")
        self.assertNotIn('software a', result[self.fw_three.uid], "foo in result fw_three")
        self.assertTrue(result['collapse'])
