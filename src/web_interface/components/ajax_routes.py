import html
from typing import Dict, List, Set

from flask import jsonify, render_template

from helperFunctions.database import ConnectTo
from helperFunctions.dataConversion import none_to_none
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_compare import CompareDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_statistic import StatisticDbViewer
from web_interface.components.component_base import ComponentBase
from web_interface.file_tree.file_tree import remove_virtual_path_from_root
from web_interface.file_tree.file_tree_node import FileTreeNode
from web_interface.file_tree.jstree_conversion import convert_to_jstree_node
from web_interface.filter import bytes_to_str_filter, encode_base64_filter
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class AjaxRoutes(ComponentBase):
    def _init_component(self):
        self._app.add_url_rule('/ajax_tree/<uid>/<root_uid>', '/ajax_tree/<uid>/<root_uid>', self._ajax_get_tree_children)
        self._app.add_url_rule('/ajax_root/<uid>/<root_uid>', 'ajax_root/<uid>/<root_uid>', self._ajax_get_tree_root)
        self._app.add_url_rule('/compare/ajax_tree/<compare_id>/<root_uid>/<uid>', 'compare/ajax_tree/<compare_id>/<root_uid>/<uid>',
                               self._ajax_get_tree_children)
        self._app.add_url_rule('/compare/ajax_common_files/<compare_id>/<feature_id>/', 'compare/ajax_common_files/<compare_id>/<feature_id>/',
                               self._ajax_get_common_files_for_compare)
        self._app.add_url_rule('/ajax_get_binary/<mime_type>/<uid>', 'ajax_get_binary/<type>/<uid>', self._ajax_get_binary)
        self._app.add_url_rule('/ajax_get_summary/<uid>/<selected_analysis>', 'ajax_get_summary/<uid>/<selected_analysis>', self._ajax_get_summary)

        self._app.add_url_rule('/ajax/stats/general', 'ajax/stats/general', self._get_general_stats)
        self._app.add_url_rule('/ajax/stats/system', 'ajax/stats/system', self._get_system_stats)

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _ajax_get_tree_children(self, uid, root_uid=None, compare_id=None):
        root_uid, compare_id = none_to_none(root_uid), none_to_none(compare_id)
        exclusive_files = self._get_exclusive_files(compare_id, root_uid)
        tree = self._generate_file_tree(root_uid, uid, exclusive_files)
        children = [
            convert_to_jstree_node(child_node)
            for child_node in tree.get_list_of_child_nodes()
        ]
        return jsonify(children)

    def _get_exclusive_files(self, compare_id, root_uid):
        if compare_id:
            with ConnectTo(CompareDbInterface, self._config) as sc:
                return sc.get_exclusive_files(compare_id, root_uid)
        return None

    def _generate_file_tree(self, root_uid: str, uid: str, whitelist: List[str]) -> FileTreeNode:
        root = FileTreeNode(None)
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            child_uids = [
                child_uid
                for child_uid in sc.get_specific_fields_of_db_entry(uid, {'files_included': 1})['files_included']
                if whitelist is None or child_uid in whitelist
            ]
            for node in sc.generate_file_tree_nodes_for_uid_list(child_uids, root_uid, whitelist):
                root.add_child_node(node)
        return root

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _ajax_get_tree_root(self, uid, root_uid):
        root = list()
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            for node in sc.generate_file_tree_level(uid, root_uid):  # only a single item in this 'iterable'
                root = [convert_to_jstree_node(node)]
        root = remove_virtual_path_from_root(root)
        return jsonify(root)

    @roles_accepted(*PRIVILEGES['compare'])
    def _ajax_get_common_files_for_compare(self, compare_id, feature_id):
        with ConnectTo(CompareDbInterface, self._config) as sc:
            result = sc.get_compare_result(compare_id)
        feature, matching_uid = feature_id.split('___')
        uid_list = result['plugins']['File_Coverage'][feature][matching_uid]
        return self._get_nice_uid_list_html(uid_list, root_uid=self._get_root_uid(matching_uid, compare_id))

    @staticmethod
    def _get_root_uid(candidate, compare_id):
        # feature_id contains a uid in individual case, in all case simply take first uid from compare
        if candidate != 'all':
            return candidate
        return compare_id.split(';')[0]

    def _get_nice_uid_list_html(self, input_data, root_uid):
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            included_files = sc.get_data_for_nice_list(input_data, None)
        number_of_unanalyzed_files = len(input_data) - len(included_files)
        return render_template(
            'generic_view/nice_fo_list.html',
            fo_list=included_files,
            number_of_unanalyzed_files=number_of_unanalyzed_files,
            omit_collapse=True,
            root_uid=root_uid
        )

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _ajax_get_binary(self, mime_type, uid):
        mime_type = mime_type.replace('_', '/')
        div = '<div style="display: block; border: 1px solid; border-color: #dddddd; padding: 5px; text-align: center">'
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            binary = sc.get_binary_and_filename(uid)[0]
        if 'text/' in mime_type:
            return '<pre style="white-space: pre-wrap">{}</pre>'.format(html.escape(bytes_to_str_filter(binary)))
        if 'image/' in mime_type:
            return '{}<img src="data:image/{} ;base64,{}" style="max-width:100%"></div>'.format(div, mime_type[6:], encode_base64_filter(binary))
        return None

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _ajax_get_summary(self, uid, selected_analysis):
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            firmware = sc.get_object(uid, analysis_filter=selected_analysis)
            summary_of_included_files = sc.get_summary(firmware, selected_analysis)
        return render_template('summary.html', summary_of_included_files=summary_of_included_files, root_uid=uid, selected_analysis=selected_analysis)

    @roles_accepted(*PRIVILEGES['status'])
    def _get_general_stats(self):
        with ConnectTo(FrontEndDbInterface, self._config) as db:
            missing_files = self._make_json_serializable(db.find_missing_files())
            missing_analyses = self._make_json_serializable(db.find_missing_analyses())
        return {
            'missing_files': len(missing_files),
            'missing_analysis': len(missing_analyses)
        }

    @roles_accepted(*PRIVILEGES['status'])
    def _get_system_stats(self):
        with ConnectTo(StatisticDbViewer, self._config) as stats_db:
            backend_data = stats_db.get_statistic("backend")
        try:
            return {
                'backend_cpu_percentage': '{}%'.format(backend_data['system']['cpu_percentage']),
                'number_of_running_analyses': len(backend_data['analysis']['current_analyses'])
            }
        except KeyError:
            return {'backend_cpu_percentage': 'n/a', 'number_of_running_analyses': 'n/a'}

    @staticmethod
    def _make_json_serializable(set_dict: Dict[str, Set[str]]) -> Dict[str, List[str]]:
        return {k: list(v) for k, v in set_dict.items()}
