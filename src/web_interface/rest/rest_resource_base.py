from flask import request
from flask_restx import Model, Resource, marshal


class RestResourceBase(Resource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = kwargs.get('config', None)

    @staticmethod
    def validate_payload_data(model: Model) -> dict:
        model.validate(request.json or {})
        return marshal(request.json, model)
