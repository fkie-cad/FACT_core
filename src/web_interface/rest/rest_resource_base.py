from flask import request
from flask_restx import Model, Resource, marshal

from storage_postgresql.db_interface_frontend import FrontEndDbInterface


class RestResourceBase(Resource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = kwargs.get('config', None)
        self._setup_db(self.config)

    @staticmethod
    def validate_payload_data(model: Model) -> dict:
        model.validate(request.json or {})
        return marshal(request.json, model)

    def _setup_db(self, config):
        pass


class RestResourceDbBase(RestResourceBase):

    def _setup_db(self, config):
        self.db = FrontEndDbInterface(config=self.config)
