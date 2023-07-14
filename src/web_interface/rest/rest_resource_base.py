from __future__ import annotations

from flask import request
from flask_restx import Model, Resource, marshal

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from storage.rest_status_interface import RestStatusInterface
    from web_interface.frontend_database import FrontendDatabase
    from intercom.front_end_binding import InterComFrontEndBinding


class RestResourceBase(Resource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db: FrontendDatabase = kwargs.get('db', None)
        self.intercom: type[InterComFrontEndBinding] = kwargs.get('intercom', None)
        self.status: RestStatusInterface = kwargs.get('status', None)

    @staticmethod
    def validate_payload_data(model: Model) -> dict:
        model.validate(request.json or {})
        return marshal(request.json, model)

    def _setup_db(self):
        pass
