# -*- coding: utf-8 -*-

import logging

from flask import render_template, request, redirect, url_for
from flask_paginate import Pagination

from helperFunctions.dataConversion import string_list_to_list, unify_string_list
from helperFunctions.web_interface import ConnectTo, apply_filters_to_query
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_compare import CompareDbInterface
from web_interface.components.component_base import ComponentBase


class CompareRoutes(ComponentBase):
    def _init_component(self):
        self._app.add_url_rule("/compare", "/compare/", self._app_show_start_compare, methods=["GET", "POST"])
        self._app.add_url_rule("/database/browse_compare", "database/browse_compare", self._app_show_browse_compare)
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
        return render_template("compare/error.html", error=result.__str__())

    def _app_show_start_compare(self):
        if request.method == "POST":
            compare_id = request.form.get("uid_list")
            redo = True if request.form.get("force") else None
            unified_compare_id = unify_string_list(compare_id)

            with ConnectTo(CompareDbInterface, self._config) as sc:
                compare_exists = sc.compare_result_is_in_db(unified_compare_id)
            if compare_exists and not redo:
                return redirect(url_for("/compare/<compare_id>", compare_id=compare_id))

            with ConnectTo(CompareDbInterface, self._config) as sc:
                err = sc.object_existence_quick_check(compare_id)
            if err is not None:
                return render_template("compare/error.html", error=err.__str__())

            with ConnectTo(InterComFrontEndBinding, self._config) as sc:
                sc.add_compare_task(unified_compare_id, force=redo)
            return render_template("compare/wait.html", compare_id=unified_compare_id)
        return render_template("compare/selection.html")

    @staticmethod
    def _create_ida_download_if_existing(result, compare_id):
        if isinstance(result, dict) and result.get("plugins", dict()).get("Ida_Diff_Highlighting", dict()).get("idb_binary"):
            return "/ida-download/{}".format(compare_id)
        return None

    def _app_show_browse_compare(self):
        page, per_page = self._get_page_items()[0:2]
        try:
            with ConnectTo(CompareDbInterface, self._config) as db_service:
                compare_list = db_service.page_compare_results(skip=per_page * (page - 1), limit=per_page)
        except Exception as exception:
            error_message = "Could not query database: {} {}".format(type(exception), str(exception))
            logging.error(error_message)
            return render_template("error.html", message=error_message)

        with ConnectTo(CompareDbInterface, self._config) as connection:
            total = connection.get_total_number_of_results()

        pagination = self._get_pagination(page=page, per_page=per_page, total=total, record_name="compare results", )
        return render_template("database/compare_browse.html", compare_list=compare_list, page=page, per_page=per_page, pagination=pagination)

    @staticmethod
    def _get_pagination(**kwargs):
        kwargs.setdefault("record_name", "records")
        return Pagination(css_framework="bootstrap3", link_size="sm", show_single_page=False,
                          format_total=True, format_number=True, **kwargs)

    def _get_page_items(self):
        page = int(request.args.get("page", 1))
        per_page = request.args.get("per_page")
        if not per_page:
            per_page = int(self._config["database"]["results_per_page"])
        else:
            per_page = int(per_page)
        offset = (page - 1) * per_page
        return page, per_page, offset
