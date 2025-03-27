from __future__ import annotations

from typing import TYPE_CHECKING

from flask import request
from flask_restx import Model, Resource, marshal

from storage.graphql.interface import GraphQlInterface

if TYPE_CHECKING:
    from intercom.front_end_binding import InterComFrontEndBinding
    from storage.redis_status_interface import RedisStatusInterface
    from web_interface.frontend_database import FrontendDatabase


class RestResourceBase(Resource):
    def __init__(self, *args, **kwargs):
        self.db: FrontendDatabase = kwargs.get('db', None)
        self.intercom: InterComFrontEndBinding = kwargs.get('intercom', None)
        self.status: RedisStatusInterface = kwargs.get('status', None)
        self.gql_interface = GraphQlInterface()
        super().__init__(*args, **kwargs)

    @staticmethod
    def validate_payload_data(model: Model) -> dict:
        model.validate(request.json or {})
        return marshal(request.json, model)

    def _setup_db(self):
        pass
