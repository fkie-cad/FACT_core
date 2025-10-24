import json

from common_helper_encoder import ReportEncoder
from flask import make_response
from flask_restx import Api

from web_interface.rest.rest_analysis import api as analysis_api
from web_interface.rest.rest_binary import api as binary_api
from web_interface.rest.rest_binary_search import api as binary_search_api
from web_interface.rest.rest_compare import api as compare_api
from web_interface.rest.rest_file_object import api as file_object_api
from web_interface.rest.rest_firmware import api as firmware_api
from web_interface.rest.rest_missing_analyses import api as missing_analyses_api
from web_interface.rest.rest_statistics import api as statistics_api
from web_interface.rest.rest_status import api as status_api


class RestBase:
    def __init__(self, app=None, db=None, intercom=None, status=None):
        self.api = Api(
            app,
            doc='/doc/',
            title='FACT Rest API',
            version='1.0',
            description='The FACT Rest API intends to offer close to 100 % functionality of FACT in a '
            'script-able and integrate-able interface. \n The API does not comply with all REST '
            'guidelines perfectly, but aims to allow understandable and efficient interfacing.',
        )

        for api in [
            analysis_api,
            binary_api,
            binary_search_api,
            compare_api,
            file_object_api,
            firmware_api,
            missing_analyses_api,
            statistics_api,
            status_api,
        ]:
            for _, _, _, kwargs in api.resources:
                kwargs['resource_class_kwargs'] = {'db': db, 'intercom': intercom, 'status': status}
            self.api.add_namespace(api)

        self._wrap_response(self.api)

    @staticmethod
    def _wrap_response(api):
        @api.representation('application/json')
        def output_json(data, code, headers=None):
            try:
                output_data = json.dumps(data, cls=ReportEncoder, sort_keys=True)
            except TypeError as error:
                raise Exception(f'Could not encode JSON: {data!r}') from error
            resp = make_response(output_data, code)
            resp.headers.extend(headers if headers else {})
            return resp
