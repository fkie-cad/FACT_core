import json

from common_helper_encoder import ReportEncoder
from flask import make_response
from flask_restful import Api

from web_interface.rest.rest_binary_search import RestBinarySearch
from .rest_compare import RestCompare
from .rest_binary import RestBinary
from .rest_file_object import RestFileObject
from .rest_firmware import RestFirmware


class RestBase:
    def __init__(self, app=None, config=None):
        self.api = Api(app)
        self.api.add_resource(RestBinary, '/rest/binary/<uid>', methods=['GET'], resource_class_kwargs={'config': config})
        self.api.add_resource(RestCompare, '/rest/compare', '/rest/compare/<compare_id>', methods=['GET', 'PUT'], resource_class_kwargs={'config': config})
        self.api.add_resource(RestFirmware, '/rest/firmware', '/rest/firmware/<uid>', methods=['GET', 'PUT'], resource_class_kwargs={'config': config})
        self.api.add_resource(RestFileObject, '/rest/file_object', '/rest/file_object/<uid>', methods=['GET'], resource_class_kwargs={'config': config})
        self.api.add_resource(RestBinarySearch, '/rest/binary_search', '/rest/binary_search/<search_id>', methods=['GET', 'POST'], resource_class_kwargs={'config': config})

        self._wrap_response(self.api)

    @staticmethod
    def _wrap_response(api):
        @api.representation('application/json')
        def output_json(data, code, headers=None):
            output_data = json.dumps(data, cls=ReportEncoder, sort_keys=True)
            resp = make_response(output_data, code)
            resp.headers.extend(headers if headers else {})
            return resp
