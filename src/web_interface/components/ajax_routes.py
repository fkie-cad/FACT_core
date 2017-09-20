# -*- coding: utf-8 -*-

import html

from common_helper_files import human_readable_file_size
from flask import jsonify

from helperFunctions.file_tree import get_correct_icon_for_mime, FileTreeNode
from helperFunctions.web_interface import ConnectTo
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_frontend import FrontEndDbInterface
from web_interface.components.component_base import ComponentBase
from web_interface.filter import encode_base64_filter, bytes_to_str_filter


class AjaxRoutes(ComponentBase):
    def _init_component(self):
        self._app.add_url_rule("/ajax_tree/<uid>", "ajax_tree/<uid>", self._ajax_get_tree_children)
        self._app.add_url_rule("/ajax_root/<uid>", "ajax_root/<uid>", self._ajax_get_tree_root)
        self._app.add_url_rule("/ajax_get_binary/<mime_type>/<uid>", "ajax_get_binary/<type>/<uid>", self._ajax_get_binary)

    def _ajax_get_tree_children(self, uid):
        children = []
        root = FileTreeNode(None)
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            child_uids = sc.get_specific_fields_of_db_entry(uid, {"files_included": 1})["files_included"]
            for child_uid in child_uids:
                for node in sc.generate_file_tree_node(child_uid, uid):
                    root.add_child_node(node)
        for child_node in root.get_list_of_child_nodes():
            child = self._generate_jstree_node(child_node)
            children.append(child)

        return jsonify(children)

    def _ajax_get_tree_root(self, uid):
        root = list()
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            for node in sc.generate_file_tree_node(uid, uid):
                root = [self._generate_jstree_node(node)]
        return jsonify(root)

    def _generate_jstree_node(self, node):
        if node.virtual:
            result = {"text": "{}".format(node.name),
                      "a_attr": {"href": "#"}, "li_attr": {"href": "#"}, "icon": "/static/file_icons/folder.png"}
        elif node.not_analyzed:
            result = {"text": "{}".format(node.name),
                      "a_attr": {"href": "/analysis/{}".format(node.uid)},
                      "li_attr": {"href": "/analysis/{}".format(node.uid)},
                      "icon": "/static/file_icons/not_analyzed.png"}
        else:
            result = {"text": "<b>{}</b> (<span style='color:gray;'>{}</span>)".format(node.name, human_readable_file_size(node.size)),
                      "a_attr": {"href": "/analysis/{}".format(node.uid)},
                      "li_attr": {"href": "/analysis/{}".format(node.uid)},
                      "icon": get_correct_icon_for_mime(node.type),
                      "data": {"uid": node.uid}}
        if node.has_children:  # current node has children
            result["children"] = [] if node.get_list_of_child_nodes() != [] else True
            for child in node.get_list_of_child_nodes():
                result_child = self._generate_jstree_node(child)
                if result_child is not None:
                    result["children"].append(result_child)
        return result

    def _ajax_get_binary(self, mime_type, uid):
        mime_type = mime_type.replace("_", "/")
        div = "<div style='display: block; border: 1px solid; border-color: #dddddd; padding: 5px; text-align: center'>"
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            binary = sc.get_binary_and_filename(uid)[0]
        if "text/" in mime_type:
            return "<pre style='white-space: pre-wrap'>{}</pre>".format(html.escape(bytes_to_str_filter(binary)))
        elif "image/" in mime_type:
            return "{}<img src='data:image/{} ;base64,{}' style='max-width:100%'></div>".format(div, mime_type[6:], encode_base64_filter(binary))
        else:
            return None
