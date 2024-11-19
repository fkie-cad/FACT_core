from __future__ import annotations

import html
import logging
from http import HTTPStatus

from flask import jsonify, render_template

from helperFunctions.data_conversion import none_to_none
from helperFunctions.database import get_shared_session
from objects.firmware import Firmware
from web_interface.components.component_base import GET, AppRoute, ComponentBase
from web_interface.components.hex_highlighting import preview_data_as_hex
from web_interface.file_tree.file_tree import remove_virtual_path_from_root
from web_interface.file_tree.file_tree_node import FileTreeNode
from web_interface.file_tree.jstree_conversion import convert_to_jstree_node
from web_interface.filter import (
    bytes_to_str_filter,
    encode_base64_filter,
    is_image,
    is_text_file,
)
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class AjaxRoutes(ComponentBase):
    @roles_accepted(*PRIVILEGES['view_analysis'])
    @AppRoute('/ajax_tree/<uid>/<root_uid>', GET)
    @AppRoute('/compare/ajax_tree/<compare_id>/<root_uid>/<uid>', GET)
    def ajax_get_tree_children(self, uid, root_uid=None, compare_id=None):
        root_uid, compare_id = none_to_none(root_uid), none_to_none(compare_id)
        exclusive_files = self._get_exclusive_files(compare_id, root_uid)
        tree = self._generate_file_tree(root_uid, uid, exclusive_files)
        children = [convert_to_jstree_node(child_node) for child_node in tree.get_list_of_child_nodes()]
        return jsonify(children)

    def _get_exclusive_files(self, compare_id, root_uid):
        if compare_id:
            return self.db.comparison.get_exclusive_files(compare_id, root_uid)
        return None

    def _generate_file_tree(self, root_uid: str | None, uid: str, whitelist: list[str]) -> FileTreeNode:
        if root_uid is None:
            # parent FW set should never be empty (if it were empty, the file would not belong to any FW)
            root_uid = list(self.db.frontend.get_parent_fw(uid)).pop()
        root = FileTreeNode(None)
        with get_shared_session(self.db.frontend) as frontend_db:
            child_uids = [
                child_uid
                for child_uid in frontend_db.get_object(uid).files_included
                if whitelist is None or child_uid in whitelist
            ]
            for node in frontend_db.generate_file_tree_nodes_for_uid_list(child_uids, root_uid, uid, whitelist):
                root.add_child_node(node)
        return root

    @roles_accepted(*PRIVILEGES['view_analysis'])
    @AppRoute('/ajax_root/<uid>/<root_uid>', GET)
    def ajax_get_tree_root(self, uid, root_uid):
        root = []
        with get_shared_session(self.db.frontend) as frontend_db:
            for node in frontend_db.generate_file_tree_level(uid, root_uid):  # only a single item in this 'iterable'
                root = [convert_to_jstree_node(node)]
        root = remove_virtual_path_from_root(root)
        return jsonify(root)

    @roles_accepted(*PRIVILEGES['compare'])
    @AppRoute('/compare/ajax_common_files/<compare_id>/<feature_id>/', GET)
    def ajax_get_common_files_for_compare(self, compare_id, feature_id):
        result = self.db.comparison.get_comparison_result(compare_id)
        feature, matching_uid = feature_id.split('___')
        uid_list = result['plugins']['File_Coverage'][feature][matching_uid]
        return self._get_nice_uid_list_html(uid_list, root_uid=self._get_root_uid(matching_uid, compare_id))

    @staticmethod
    def _get_root_uid(candidate, compare_id):
        # feature_id contains an UID in individual case, in all case simply take first uid from compare
        if candidate != 'all':
            return candidate
        return compare_id.split(';')[0]

    def _get_nice_uid_list_html(self, input_data, root_uid):
        included_files = self.db.frontend.get_data_for_nice_list(input_data, None)
        number_of_unanalyzed_files = len(input_data) - len(included_files)
        return render_template(
            'generic_view/nice_fo_list.html',
            fo_list=included_files,
            number_of_unanalyzed_files=number_of_unanalyzed_files,
            omit_collapse=True,
            root_uid=root_uid,
        )

    @roles_accepted(*PRIVILEGES['view_analysis'])
    @AppRoute('/ajax_get_binary/<mime_type>/<uid>', GET)
    def ajax_get_binary(self, mime_type, uid):
        mime_type = mime_type.replace('_', '/')
        binary = self.intercom.get_binary_and_filename(uid)[0]
        if is_text_file(mime_type):
            return (
                '<pre class="line_numbering" style="white-space: pre-wrap">'
                f'{html.escape(bytes_to_str_filter(binary))}</pre>'
            )
        if is_image(mime_type):
            return (
                '<div style="display: block; border: 1px solid; border-color: #dddddd; padding: 5px; '
                f'text-align: center"><img src="data:image/{mime_type[6:]} ;base64,{encode_base64_filter(binary)}" '
                'style="max-width:100%"></div>'
            )
        return None

    @roles_accepted(*PRIVILEGES['view_analysis'])
    @AppRoute('/ajax_get_hex_preview/<string:uid>/<int:offset>/<int:length>', GET)
    def ajax_get_hex_preview(self, uid: str, offset: int, length: int) -> str:
        partial_binary = self.intercom.peek_in_binary(uid, offset, length)
        hex_dump = preview_data_as_hex(partial_binary, offset=offset)
        return f'<pre style="white-space: pre-wrap; margin-bottom: 0;">\n{hex_dump}\n</pre>'

    @roles_accepted(*PRIVILEGES['view_analysis'])
    @AppRoute('/ajax_get_summary/<uid>/<selected_analysis>', GET)
    def ajax_get_summary(self, uid, selected_analysis):
        with get_shared_session(self.db.frontend) as frontend_db:
            firmware = frontend_db.get_object(uid, analysis_filter=selected_analysis)
            summary_of_included_files = frontend_db.get_summary(firmware, selected_analysis)
            root_uid = uid if isinstance(firmware, Firmware) else frontend_db.get_root_uid(uid)
        return render_template(
            'summary.html',
            summary_of_included_files=summary_of_included_files,
            root_uid=root_uid,
            selected_analysis=selected_analysis,
        )

    @roles_accepted(*PRIVILEGES['status'])
    @AppRoute('/ajax/stats/system', GET)
    def get_system_stats(self):
        backend_data = self.db.stats_viewer.get_statistic('backend')
        analysis_status = self.status.get_analysis_status()
        try:
            return {
                'backend_cpu_percentage': f"{backend_data['system']['cpu_percentage']}%",
                'number_of_running_analyses': len(analysis_status['current_analyses']),
            }
        except (KeyError, TypeError):
            return {'backend_cpu_percentage': 'n/a', 'number_of_running_analyses': 'n/a'}

    @roles_accepted(*PRIVILEGES['status'])
    @AppRoute('/ajax/system_health', GET)
    def get_system_health_update(self):
        return {
            'systemHealth': self.db.stats_viewer.get_stats_list('backend', 'frontend', 'database'),
            'analysisStatus': self.status.get_analysis_status(),
        }

    @roles_accepted(*PRIVILEGES['cancel_analysis'])
    @AppRoute('/ajax/cancel_analysis/<root_uid>', GET)
    def cancel_analysis(self, root_uid: str):
        logging.info(f'Received analysis cancel request for {root_uid}')
        self.intercom.cancel_analysis(root_uid=root_uid)
        return {}, HTTPStatus.OK
