# -*- coding: utf-8 -*-

from flask import render_template, request, redirect, url_for

from helperFunctions.dataConversion import string_list_to_list, unify_string_list
from helperFunctions.web_interface import ConnectTo
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_compare import CompareDbInterface
from web_interface.components.component_base import ComponentBase


class CompareRoutes(ComponentBase):
    def _init_component(self):
        self._app.add_url_rule("/compare", "/compare/", self._app_show_start_compare, methods=["GET", "POST"])
        self._app.add_url_rule("/compare/<compare_id>", "/compare/<compare_id>", self._app_show_compare_result)

    def _app_show_compare_result(self, compare_id):
        compare_id = unify_string_list(compare_id)
        with ConnectTo(CompareDbInterface, self._config) as sc:
            result = sc.get_compare_result(compare_id)
        download_link = self._create_ida_download_if_existing(result, compare_id)
        if result is None:
            return render_template("compare/wait.html", compare_id=compare_id)
        elif isinstance(result, dict):
            uid_list = string_list_to_list(compare_id)
            return render_template("compare/compare.html", result=result, uid_list=uid_list, download_link=download_link)
        else:
            return render_template("compare/error.html", error=result.__str__())

    def _app_show_start_compare(self):
        if request.method == "POST":
            compare_id = request.form.get("uid_list")
            redo = True if request.form.get("force") else None
            unified_compare_id = unify_string_list(compare_id)

            with ConnectTo(CompareDbInterface, self._config) as sc:
                compare_exists = sc.compare_result_is_in_db(unified_compare_id)
            if not compare_exists or redo:
                with ConnectTo(CompareDbInterface, self._config) as sc:
                    err = sc.object_existence_quick_check(compare_id)
                if err is None:
                    with ConnectTo(InterComFrontEndBinding, self._config) as sc:
                        sc.add_compare_task(unified_compare_id, force=redo)
                    return render_template("compare/wait.html", compare_id=unified_compare_id)
                else:
                    return render_template("compare/error.html", error=err.__str__())
            else:
                return redirect(url_for("/compare/<compare_id>", compare_id=compare_id))
        return render_template("compare/selection.html")

    @staticmethod
    def _create_ida_download_if_existing(result, compare_id):
        if isinstance(result, dict) and result.get("plugins", dict()).get("Ida_Diff_Highlighting", dict()).get("idb_binary"):
            return "/ida-download/{}".format(compare_id)
        else:
            return None
