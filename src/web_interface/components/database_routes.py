import json
import logging
from datetime import datetime
from itertools import chain

from flask import redirect, render_template, request, url_for
from sqlalchemy.exc import SQLAlchemyError

from helperFunctions.config import read_list_from_config
from helperFunctions.data_conversion import make_unicode_string
from helperFunctions.database import ConnectTo, get_shared_session
from helperFunctions.task_conversion import get_file_name_and_binary_from_request
from helperFunctions.uid import is_uid
from helperFunctions.web_interface import apply_filters_to_query, filter_out_illegal_characters
from helperFunctions.yara_binary_search import get_yara_error, is_valid_yara_rule_file
from storage.query_conversion import QueryConversionException
from web_interface.components.component_base import GET, POST, AppRoute, ComponentBase
from web_interface.pagination import extract_pagination_from_request, get_pagination
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class DatabaseRoutes(ComponentBase):
    @staticmethod
    def _add_date_to_query(query, date):
        try:
            start_str = datetime.strptime(date.replace('\'', ''), '%B %Y').strftime('%Y-%m')
            date_query = {'release_date': {'$regex': start_str}}
            if query == {}:
                query = date_query
            else:
                query.update(date_query)
            return query
        except Exception:
            return query

    @roles_accepted(*PRIVILEGES['basic_search'])
    @AppRoute('/database/browse', GET)
    def browse_database(self, query: str = '{}', only_firmwares=False, inverted=False):
        page, per_page = extract_pagination_from_request(request, self._config)[0:2]
        search_parameters = self._get_search_parameters(query, only_firmwares, inverted)

        with get_shared_session(self.db.frontend) as frontend_db:
            try:
                firmware_list = self._search_database(
                    search_parameters['query'],
                    skip=per_page * (page - 1),
                    limit=per_page,
                    only_firmwares=search_parameters['only_firmware'],
                    inverted=search_parameters['inverted'],
                )
                if self._query_has_only_one_result(firmware_list, search_parameters['query']):
                    return redirect(url_for('show_analysis', uid=firmware_list[0][0]))
            except QueryConversionException as exception:
                error_message = exception.get_message()
                return render_template('error.html', message=error_message)
            except Exception as err:
                error_message = 'Could not query database'
                logging.error(error_message + f' due to exception: {err}', exc_info=True)  # pylint: disable=logging-not-lazy
                return render_template('error.html', message=error_message)

            total = frontend_db.get_number_of_total_matches(
                search_parameters['query'], search_parameters['only_firmware'], inverted=search_parameters['inverted'],
            )
            device_classes = frontend_db.get_device_class_list()
            vendors = frontend_db.get_vendor_list()

        pagination = get_pagination(page=page, per_page=per_page, total=total, record_name='firmwares')
        return render_template(
            'database/database_browse.html',
            firmware_list=firmware_list,
            page=page,
            per_page=per_page,
            pagination=pagination,
            device_classes=device_classes,
            vendors=vendors,
            current_class=str(request.args.get('device_class')),
            current_vendor=str(request.args.get('vendor')),
            search_parameters=search_parameters,
        )

    @roles_accepted(*PRIVILEGES['pattern_search'])
    @AppRoute('/database/browse_binary_search_history', GET)
    def browse_searches(self):
        page, per_page, offset = extract_pagination_from_request(request, self._config)
        try:
            with get_shared_session(self.db.frontend) as frontend_db:
                searches = frontend_db.search_query_cache(offset=offset, limit=per_page)
                total = frontend_db.get_total_cached_query_count()
        except SQLAlchemyError as exception:
            error_message = 'Could not query database'
            logging.error(error_message + f'due to exception: {exception}', exc_info=True)  # pylint: disable=logging-not-lazy
            return render_template('error.html', message=error_message)

        pagination = get_pagination(page=page, per_page=per_page, total=total)
        return render_template(
            'database/database_binary_search_history.html',
            searches_list=searches,
            page=page,
            per_page=per_page,
            pagination=pagination,
        )

    def _get_search_parameters(self, query, only_firmware, inverted):
        '''
        This function prepares the requested search by parsing all necessary parameters.
        In case of a binary search, indicated by the query being an uid instead of a dict, the cached search result is
        retrieved.
        '''
        search_parameters = {}
        if request.args.get('query'):
            query = request.args.get('query')
            if is_uid(query):
                cached_query = self.db.frontend.get_query_from_cache(query)
                query = cached_query.query
                search_parameters['query_title'] = cached_query.yara_rule
        search_parameters['only_firmware'] = request.args.get('only_firmwares') == 'True' if request.args.get(
            'only_firmwares',
        ) else only_firmware
        search_parameters['inverted'] = request.args.get('inverted',
                                                         ) == 'True' if request.args.get('inverted') else inverted
        search_parameters['query'] = apply_filters_to_query(request, query)
        if 'query_title' not in search_parameters:
            search_parameters['query_title'] = search_parameters['query']
        if request.args.get('date'):
            search_parameters['query'] = self._add_date_to_query(search_parameters['query'], request.args.get('date'))
        return search_parameters

    @staticmethod
    def _query_has_only_one_result(result_list, query):
        return len(result_list) == 1 and query != '{}'

    def _search_database(self, query, skip=0, limit=0, only_firmwares=False, inverted=False):
        meta_list = self.db.frontend.generic_search(
            query, skip, limit, only_fo_parent_firmware=only_firmwares, inverted=inverted, as_meta=True,
        )
        if not isinstance(meta_list, list):
            raise Exception(meta_list)
        return sorted(meta_list, key=lambda x: x[1].lower())

    def _build_search_query(self):
        query = {}
        for key in ['device_class', 'vendor']:
            if key in request.form and request.form[key]:
                choices = list(dict(request.form.lists())[key])
                query[key] = {'$in': choices}
        for key in ['file_name', 'device_name', 'version', 'release_date']:
            if request.form[key]:
                query[key] = {'$like': request.form[key]}
        if request.form['hash_value']:
            self._add_hash_query_to_query(query, request.form['hash_value'])
        if 'tags' in request.form and request.form['tags']:
            tags = list(dict(request.form.lists())['tags'])
            query['firmware_tags'] = {'$overlap': tags}
        return json.dumps(query)

    def _add_hash_query_to_query(self, query, value):
        hash_types = read_list_from_config(self._config, 'file_hashes', 'hashes')
        hash_query = {f'processed_analysis.file_hashes.{hash_type}': value for hash_type in hash_types}
        query.update({'$or': hash_query})

    @roles_accepted(*PRIVILEGES['basic_search'])
    @AppRoute('/database/search', POST)
    def start_basic_search(self):
        query = self._build_search_query()
        return redirect(url_for('browse_database', query=query))

    @roles_accepted(*PRIVILEGES['basic_search'])
    @AppRoute('/database/search', GET)
    def show_basic_search(self):
        with get_shared_session(self.db.frontend) as frontend_db:
            device_classes = frontend_db.get_device_class_list()
            vendors = frontend_db.get_vendor_list()
            tags = frontend_db.get_tag_list()
        return render_template(
            'database/database_search.html', device_classes=device_classes, vendors=vendors, tag_list=tags,
        )

    @roles_accepted(*PRIVILEGES['advanced_search'])
    @AppRoute('/database/advanced_search', POST)
    def start_advanced_search(self):
        try:
            query = json.loads(request.form['advanced_search'])  # check for syntax errors
            only_firmwares = request.form.get('only_firmwares') is not None
            inverted = request.form.get('inverted') is not None
            if not isinstance(query, dict):
                raise Exception('Error: search query invalid (wrong type)')
            return redirect(
                url_for('browse_database', query=json.dumps(query), only_firmwares=only_firmwares, inverted=inverted),
            )
        except Exception as error:
            return self.show_advanced_search(error=error)

    @roles_accepted(*PRIVILEGES['advanced_search'])
    @AppRoute('/database/advanced_search', GET)
    def show_advanced_search(self, error=None):
        database_structure = self.db.frontend.create_analysis_structure()
        return render_template(
            'database/database_advanced_search.html', error=error, database_structure=database_structure,
        )

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
                    with ConnectTo(self.intercom, self._config) as connection:
                        request_id = connection.add_binary_search_request(yara_rule_file, firmware_uid)
                    return redirect(
                        url_for('get_binary_search_results', request_id=request_id, only_firmware=only_firmware),
                    )
                error = f'Error in YARA rules: {get_yara_error(yara_rule_file)} (pre-compiled rules are not supported here!)'
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
        return self.db.frontend.is_firmware(firmware_uid)

    @roles_accepted(*PRIVILEGES['pattern_search'])
    @AppRoute('/database/binary_search_results', GET)
    def get_binary_search_results(self):
        firmware_dict, error, yara_rules = None, None, None
        if request.args.get('request_id'):
            request_id = request.args.get('request_id')
            with ConnectTo(self.intercom, self._config) as connection:
                result, yara_rules = connection.get_binary_search_result(request_id)
            if isinstance(result, str):
                error = result
            elif result is not None:
                yara_rules = make_unicode_string(yara_rules[0])
                joined_results = self._join_results(result)
                query_uid = self._store_binary_search_query(joined_results, yara_rules)
                return redirect(
                    url_for('browse_database', query=query_uid, only_firmwares=request.args.get('only_firmware')),
                )
        else:
            error = 'No request ID found'
            request_id = None
        return render_template(
            'database/database_binary_search_results.html',
            result=firmware_dict,
            error=error,
            request_id=request_id,
            yara_rules=yara_rules,
        )

    def _store_binary_search_query(self, binary_search_results: list, yara_rules: str) -> str:
        query = '{"_id": {"$in": ' + str(binary_search_results).replace('\'', '"') + '}}'
        query_uid = self.db.editing.add_to_search_query_cache(query, query_title=yara_rules)
        return query_uid

    @staticmethod
    def _join_results(result_dict):
        return list(set(chain(*result_dict.values())))

    @roles_accepted(*PRIVILEGES['basic_search'])
    @AppRoute('/database/quick_search', GET)
    def start_quick_search(self):  # pylint: disable=no-self-use
        search_term = filter_out_illegal_characters(request.args.get('search_term'))
        if search_term is None:
            return render_template('error.html', message='Search string not found')
        query = {
            '$or': {
                'device_name': {
                    '$like': search_term
                },
                'vendor': {
                    '$like': search_term
                },
                'file_name': {
                    '$like': search_term
                },
                'sha256': search_term,
                'firmware_tags': search_term,
            }
        }
        return redirect(url_for('browse_database', query=json.dumps(query)))
