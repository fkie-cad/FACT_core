import json
from configparser import ConfigParser

from common_helper_encoder import ReportEncoder
from flask import make_response
from flask_restx import Api
from flask_restx.namespace import Namespace

from web_interface.rest.rest_binary import api as binary_api
from web_interface.rest.rest_binary_search import api as binary_search_api
from web_interface.rest.rest_compare import api as compare_api
from web_interface.rest.rest_file_object import api as file_object_api
from web_interface.rest.rest_firmware import api as firmware_api
from web_interface.rest.rest_missing_analyses import api as missing_analyses_api
from web_interface.rest.rest_statistics import api as statistics_api
from web_interface.rest.rest_status import api as status_api


class RestBase:
    def __init__(self, app=None, config=None):
        self.api = Api(app, doc='/doc/', title='FACT Rest API', version='1.0',
                       description='The FACT Rest API intends to offer close to 100 % functionality of FACT in a '
                                   'script-able and integrate-able interface. \n The API does not comply with all REST '
                                   'guidelines perfectly, but aims to allow understandable and efficient interfacing.')

        self.pass_config_and_add_namespace(firmware_api, config)
        self.pass_config_and_add_namespace(file_object_api, config)
        self.pass_config_and_add_namespace(compare_api, config)
        self.pass_config_and_add_namespace(binary_api, config)
        self.pass_config_and_add_namespace(binary_search_api, config)
        self.pass_config_and_add_namespace(statistics_api, config)
        self.pass_config_and_add_namespace(status_api, config)
        self.pass_config_and_add_namespace(missing_analyses_api, config)

        self._wrap_response(self.api)

    @staticmethod
    def _pass_config_to_init(config: ConfigParser, api: Namespace):
        for _, _, _, kwargs in api.resources:
            kwargs['resource_class_kwargs'] = {'config': config}

    @staticmethod
    def _wrap_response(api):
        @api.representation('application/json')
        def output_json(data, code, headers=None):  # pylint: disable=unused-variable
            output_data = json.dumps(data, cls=ReportEncoder, sort_keys=True)
            resp = make_response(output_data, code)
            resp.headers.extend(headers if headers else {})
            return resp

    def pass_config_and_add_namespace(self, imported_api, config: ConfigParser):
        self._pass_config_to_init(config, imported_api)
        self.api.add_namespace(imported_api)
