import json
import logging
from datetime import datetime
from itertools import chain

from dateutil.relativedelta import relativedelta
from flask import redirect, render_template, request, url_for

from helperFunctions.config import read_list_from_config
from helperFunctions.data_conversion import make_unicode_string
from helperFunctions.database import ConnectTo
from helperFunctions.mongo_task_conversion import get_file_name_and_binary_from_request
from helperFunctions.uid import is_uid
from helperFunctions.web_interface import apply_filters_to_query, filter_out_illegal_characters
from helperFunctions.yara_binary_search import get_yara_error, is_valid_yara_rule_file
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_frontend_editing import FrontendEditingDbInterface
from web_interface.components.component_base import GET, POST, AppRoute, ComponentBase
from web_interface.pagination import extract_pagination_from_request, get_pagination
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class DatabaseRoutes(ComponentBase):

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
        except Exception:
            return query

    @roles_accepted(*PRIVILEGES['basic_search'])
    @AppRoute('/database/browse', GET)
    def browse_database(self, query: str = '{}', only_firmwares=False, inverted=False):
        page, per_page = extract_pagination_from_request(request, self._config)[0:2]
        search_parameters = self._get_search_parameters(query, only_firmwares, inverted)
        try:
            firmware_list = self._search_database(
                search_parameters['query'], skip=per_page * (page - 1), limit=per_page,
                only_firmwares=search_parameters['only_firmware'], inverted=search_parameters['inverted']
            )
            if self._query_has_only_one_result(firmware_list, search_parameters['query']):
                return redirect(url_for('show_analysis', uid=firmware_list[0][0]))
        except Exception as err:
            error_message = f'Could not query database: {str(err)}'
            logging.error(error_message, exc_info=True)
            return render_template('error.html', message=error_message)

        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            total = connection.get_number_of_total_matches(search_parameters['query'], search_parameters['only_firmware'], inverted=search_parameters['inverted'])
            device_classes = connection.get_device_class_list()
            vendors = connection.get_vendor_list()

        pagination = get_pagination(page=page, per_page=per_page, total=total, record_name='firmwares')
        return render_template(
            'database/database_browse.html',
            firmware_list=firmware_list,
            page=page, per_page=per_page,
            pagination=pagination,
            device_classes=device_classes,
            vendors=vendors,
            current_class=str(request.args.get('device_class')),
            current_vendor=str(request.args.get('vendor')),
            search_parameters=search_parameters
        )

    def _get_search_parameters(self, query, only_firmware, inverted):
        '''
        This function prepares the requested search by parsing all necessary parameters.
        In case of a binary search, indicated by the query being an uid instead of a dict, the cached search result is
        retrieved.
        '''
        search_parameters = dict()
        if request.args.get('query'):
            query = request.args.get('query')
            if is_uid(query):
                with ConnectTo(FrontEndDbInterface, self._config) as connection:
                    cached_query = connection.get_query_from_cache(query)
                    query = cached_query['search_query']
                    search_parameters['query_title'] = cached_query['query_title']
        search_parameters['only_firmware'] = request.args.get('only_firmwares') == 'True' if request.args.get('only_firmwares') else only_firmware
        search_parameters['inverted'] = request.args.get('inverted') == 'True' if request.args.get('inverted') else inverted
        search_parameters['query'] = apply_filters_to_query(request, query)
        if 'query_title' not in search_parameters.keys():
            search_parameters['query_title'] = search_parameters['query']
        if request.args.get('date'):
            search_parameters['query'] = self._add_date_to_query(search_parameters['query'], request.args.get('date'))
        return search_parameters

    @staticmethod
    def _query_has_only_one_result(result_list, query):
        return len(result_list) == 1 and query != '{}'

    def _search_database(self, query, skip=0, limit=0, only_firmwares=False, inverted=False):
        sorted_meta_list = list()
        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            result = connection.generic_search(query, skip, limit, only_fo_parent_firmware=only_firmwares, inverted=inverted)
            if not isinstance(result, list):
                raise Exception(result)
            if query not in ('{}', {}):
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
        hash_types = read_list_from_config(self._config, 'file_hashes', 'hashes')
        hash_query = [{f'processed_analysis.file_hashes.{hash_type}': value} for hash_type in hash_types]
        query.update({'$or': hash_query})

    @roles_accepted(*PRIVILEGES['basic_search'])
    @AppRoute('/database/search', POST)
    def start_basic_search(self):
        query = self._build_search_query()
        return redirect(url_for('browse_database', query=query))

    @roles_accepted(*PRIVILEGES['basic_search'])
    @AppRoute('/database/search', GET)
    def show_basic_search(self):
        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            device_classes = connection.get_device_class_list()
            vendors = connection.get_vendor_list()
        return render_template('database/database_search.html', device_classes=device_classes, vendors=vendors)

    @roles_accepted(*PRIVILEGES['advanced_search'])
    @AppRoute('/database/advanced_search', POST)
    def start_advanced_search(self):
        try:
            query = json.loads(request.form['advanced_search'])  # check for syntax errors
            only_firmwares = request.form.get('only_firmwares') is not None
            inverted = request.form.get('inverted') is not None
            if not isinstance(query, dict):
                raise Exception('Error: search query invalid (wrong type)')
            return redirect(url_for('browse_database', query=json.dumps(query), only_firmwares=only_firmwares, inverted=inverted))
        except Exception as error:
            return self.show_advanced_search(error=error)

    @roles_accepted(*PRIVILEGES['advanced_search'])
    @AppRoute('/database/advanced_search', GET)
    def show_advanced_search(self, error=None):
        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            database_structure = connection.create_analysis_structure()
        return render_template('database/database_advanced_search.html', error=error, database_structure=database_structure)

    @roles_accepted(*PRIVILEGES['pattern_search'])
    @AppRoute('/database/binary_search', GET, POST)
    def start_binary_search(self):
        error = None
        if request.method == 'POST':
            yara_rule_file, firmware_uid, only_firmware = self._get_items_from_binary_search_request(request)
            if firmware_uid and not self._firmware_is_in_db(firmware_uid):
                error = f'Error: Firmware with UID {repr(firmware_uid)} not found in database'
            elif yara_rule_file is not None:
                if is_valid_yara_rule_file(yara_rule_file):
                    with ConnectTo(InterComFrontEndBinding, self._config) as connection:
                        request_id = connection.add_binary_search_request(yara_rule_file, firmware_uid)
                    return redirect(url_for('get_binary_search_results', request_id=request_id, only_firmware=only_firmware))
                error = f'Error in YARA rules: {get_yara_error(yara_rule_file)}'
            else:
                error = 'please select a file or enter rules in the text area'
        return render_template('database/database_binary_search.html', error=error)

    def _get_items_from_binary_search_request(self, req):
        yara_rule_file = None
        if 'file' in req.files and req.files['file']:
            _, yara_rule_file = get_file_name_and_binary_from_request(req, self._config)
        elif req.form['textarea']:
            yara_rule_file = req.form['textarea'].encode()
        firmware_uid = req.form.get('firmware_uid') if req.form.get('firmware_uid') else None
        only_firmware = req.form.get('only_firmware') is not None
        return yara_rule_file, firmware_uid, only_firmware

    def _firmware_is_in_db(self, firmware_uid: str) -> bool:
        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            return connection.is_firmware(firmware_uid)

    @roles_accepted(*PRIVILEGES['pattern_search'])
    @AppRoute('/database/binary_search_results', GET)
    def get_binary_search_results(self):
        firmware_dict, error, yara_rules = None, None, None
        if request.args.get('request_id'):
            request_id = request.args.get('request_id')
            with ConnectTo(InterComFrontEndBinding, self._config) as connection:
                result, yara_rules = connection.get_binary_search_result(request_id)
            if isinstance(result, str):
                error = result
            elif result is not None:
                yara_rules = make_unicode_string(yara_rules[0])
                joined_results = self._join_results(result)
                query_uid = self._store_binary_search_query(joined_results, yara_rules)
                return redirect(url_for('browse_database', query=query_uid, only_firmwares=request.args.get('only_firmware')))
        else:
            error = 'No request ID found'
            request_id = None
        return render_template(
            'database/database_binary_search_results.html',
            result=firmware_dict, error=error, request_id=request_id, yara_rules=yara_rules
        )

    def _store_binary_search_query(self, binary_search_results: list, yara_rules: str) -> str:
        query = '{"_id": {"$in": ' + str(binary_search_results).replace('\'', '"') + '}}'
        with ConnectTo(FrontendEditingDbInterface, self._config) as connection:
            query_uid = connection.add_to_search_query_cache(query, query_title=yara_rules)
        return query_uid

    @staticmethod
    def _join_results(result_dict):
        return list(set(chain(*result_dict.values())))

    @roles_accepted(*PRIVILEGES['basic_search'])
    @AppRoute('/database/quick_search', GET)
    def start_quick_search(self):
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
        return redirect(url_for('browse_database', query=query))
