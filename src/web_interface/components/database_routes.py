# -*- coding: utf-8 -*-
import json
import logging
import sys
from datetime import datetime

from dateutil.relativedelta import relativedelta
from flask import render_template, request, redirect, url_for
from flask_paginate import Pagination

from helperFunctions.dataConversion import make_unicode_string
from helperFunctions.mongo_task_conversion import get_file_name_and_binary_from_request
from helperFunctions.web_interface import ConnectTo, apply_filters_to_query, filter_out_illegal_characters
from helperFunctions.yara_binary_search import YaraRuleError, is_valid_yara_rule_file, get_yara_error
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_frontend import FrontEndDbInterface
from web_interface.components.component_base import ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class DatabaseRoutes(ComponentBase):

    def _init_component(self):
        self._app.add_url_rule('/database/browse', 'database/browse', self._app_show_browse_database)
        self._app.add_url_rule('/database/search', 'database/search', self._app_show_search_database, methods=['GET', 'POST'])
        self._app.add_url_rule('/database/advanced_search', 'database/advanced_search', self._app_show_advanced_search, methods=['GET', 'POST'])
        self._app.add_url_rule('/database/binary_search', 'database/binary_search', self._app_start_binary_search, methods=['GET', 'POST'])
        self._app.add_url_rule('/database/quick_search', 'database/quick_search', self._app_start_quick_search, methods=['GET'])
        self._app.add_url_rule('/database/database_binary_search_results.html', 'database/database_binary_search_results.html', self._app_show_binary_search_results)

    def _get_page_items(self):
        page = int(request.args.get('page', 1))
        per_page = request.args.get('per_page')
        if not per_page:
            per_page = int(self._config['database']['results_per_page'])
        else:
            per_page = int(per_page)
        offset = (page - 1) * per_page
        return page, per_page, offset

    @staticmethod
    def _get_pagination(**kwargs):
        kwargs.setdefault('record_name', 'records')
        return Pagination(css_framework='bootstrap3', link_size='sm', show_single_page=False,
                          format_total=True, format_number=True, **kwargs)

    @staticmethod
    def _add_date_to_query(query, date):
        try:
            start_date = datetime.strptime(date.replace('\'', ''), '%B %Y')
            end_date = start_date + relativedelta(months=1)
            date_query = {'release_date': {'$gte': start_date, '$lt': end_date}}
            if query == {}:
                query = date_query
            else:
                query = {'$and': [query, date_query]}
            return query
        except:
            return query

    @roles_accepted(*PRIVILEGES['basic_search'])
    def _app_show_browse_database(self, query='{}', only_firmwares=False):
        page, per_page = self._get_page_items()[0:2]
        if request.args.get('query'):
            query = request.args.get('query')
        if request.args.get('only_firmwares'):
            only_firmwares = request.args.get('only_firmwares') == 'True'
        query = apply_filters_to_query(request, query)
        if request.args.get('date'):
            query = self._add_date_to_query(query, request.args.get('date'))
        try:
            firmware_list = self._search_database(query, skip=per_page * (page - 1), limit=per_page, only_firmwares=only_firmwares)
            if self._query_has_only_one_result(firmware_list, query):
                uid = firmware_list[0][0]
                return redirect(url_for('analysis/<uid>', uid=uid))
        except Exception as e:
            error_message = 'Could not query database: {} {}'.format(sys.exc_info()[0].__name__, e)
            logging.error(error_message)
            return render_template('error.html', message=error_message)

        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            total = connection.get_number_of_total_matches(query, only_firmwares)
            device_classes = connection.get_device_class_list()
            vendors = connection.get_vendor_list()

        pagination = self._get_pagination(page=page, per_page=per_page, total=total, record_name='firmwares', )
        return render_template('database/database_browse.html', firmware_list=firmware_list, page=page, per_page=per_page, pagination=pagination,
                               device_classes=device_classes, vendors=vendors, current_class=str(request.args.get('device_class')), current_vendor=str(request.args.get('vendor')))

    @staticmethod
    def _query_has_only_one_result(result_list, query):
        return len(result_list) == 1 and query != '{}'

    def _search_database(self, query, skip=0, limit=0, only_firmwares=False):
        sorted_meta_list = list()
        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            result = connection.generic_search(query, skip, limit, only_fo_parent_firmware=only_firmwares)
            if not type(result) == list:
                raise Exception(result)
            if not (query == '{}' or query == {}):
                firmware_list = [connection.firmwares.find_one(uid) or connection.file_objects.find_one(uid) for uid in result]
            else:  # if search query is empty: get only firmware objects
                firmware_list = [connection.firmwares.find_one(uid) for uid in result]
            sorted_meta_list = sorted(connection.get_meta_list(firmware_list), key=lambda x: x[1].lower())

        return sorted_meta_list

    def _build_search_query(self):
        query = {}
        if request.form['device_class_dropdown']:
            query.update({'device_class': request.form['device_class_dropdown']})
        for item in ['file_name', 'vendor', 'device_name', 'version', 'release_date']:
            if request.form[item]:
                query.update({item: {'$options': 'si', '$regex': request.form[item]}})
        if request.form['hash_value']:
            self._add_hash_query_to_query(query, request.form['hash_value'])
        return json.dumps(query)

    def _add_hash_query_to_query(self, query, value):
        hash_types = self._config['file_hashes']['hashes'].split(', ')
        hash_query = [{'processed_analysis.file_hashes.{}'.format(hash_type): value} for hash_type in hash_types]
        query.update({'$or': hash_query})

    @roles_accepted(*PRIVILEGES['basic_search'])
    def _app_show_search_database(self):
        if request.method == 'POST':
            query = self._build_search_query()
            return redirect(url_for('database/browse', query=query))
        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            device_classes = connection.get_device_class_list()
            vendors = connection.get_vendor_list()
        return render_template('database/database_search.html', device_classes=device_classes, vendors=vendors)

    @roles_accepted(*PRIVILEGES['advanced_search'])
    def _app_show_advanced_search(self, error=None):
        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            database_structure = connection.create_analysis_structure()
        if request.method == 'POST':
            try:
                query = json.loads(request.form['advanced_search'])  # check for syntax errors
                only_firmwares = request.form.get('only_firmwares') is not None
                if not isinstance(query, dict):
                    raise Exception('Error: search query invalid (wrong type)')
                return redirect(url_for('database/browse', query=json.dumps(query), only_firmwares=only_firmwares))
            except Exception as e:
                error = e
        return render_template('database/database_advanced_search.html', error=error, database_structure=database_structure)

    @staticmethod
    def _get_yara_rule_file_from_request(request):
        yara_rule_file = None
        if 'file' in request.files and request.files['file']:
            _, yara_rule_file = get_file_name_and_binary_from_request(request)
        elif request.form['textarea']:
            yara_rule_file = request.form['textarea'].encode()
        return yara_rule_file

    def _build_firmware_dict_for_binary_search(self, uid_dict):
        firmware_dict = {}
        for rule in uid_dict:
            with ConnectTo(FrontEndDbInterface, self._config) as connection:
                firmware_list = [
                    connection.firmwares.find_one(uid) or
                    connection.file_objects.find_one(uid)
                    for uid in uid_dict[rule]
                ]
                firmware_dict[rule] = sorted(connection.get_meta_list(firmware_list))
        return firmware_dict

    @roles_accepted(*PRIVILEGES['pattern_search'])
    def _app_start_binary_search(self):
        error = None
        if request.method == 'POST':
            yara_rule_file = self._get_yara_rule_file_from_request(request)
            if yara_rule_file is not None:
                if is_valid_yara_rule_file(yara_rule_file):
                    with ConnectTo(InterComFrontEndBinding, self._config) as connection:
                        request_id = connection.add_binary_search_request(yara_rule_file)
                    return redirect(url_for('database/database_binary_search_results.html', request_id=request_id))
                else:
                    error = 'Error in YARA rules: {}'.format(get_yara_error(yara_rule_file))
            else:
                error = 'please select a file or enter rules in the text area'
        return render_template('database/database_binary_search.html', error=error)

    @roles_accepted(*PRIVILEGES['pattern_search'])
    def _app_show_binary_search_results(self):
        firmware_dict, error, yara_rules = None, None, None
        if request.args.get('request_id'):
            request_id = request.args.get('request_id')
            with ConnectTo(InterComFrontEndBinding, self._config) as connection:
                result, yara_rules = connection.get_binary_search_result(request_id)
            if type(result) == YaraRuleError:
                error = '{}'.format(result)
            elif result is not None:
                yara_rules = make_unicode_string(yara_rules)
                firmware_dict = self._build_firmware_dict_for_binary_search(result)
        else:
            error = 'No request ID found'
            request_id = None
        return render_template('database/database_binary_search_results.html', result=firmware_dict, error=error,
                               request_id=request_id, yara_rules=yara_rules)

    @roles_accepted(*PRIVILEGES['basic_search'])
    def _app_start_quick_search(self):
        search_term = filter_out_illegal_characters(request.args.get('search_term'))
        if search_term is None:
            return render_template('error.html', message='Search string not found')
        query = {}
        self._add_hash_query_to_query(query, search_term)
        query['$or'].extend([
            {'device_name': {'$options': 'si', '$regex': search_term}},
            {'vendor': {'$options': 'si', '$regex': search_term}},
            {'file_name': {'$options': 'si', '$regex': search_term}}
        ])
        query = json.dumps(query)
        return redirect(url_for('database/browse', query=query))
