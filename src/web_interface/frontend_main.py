from __future__ import annotations

import logging

from intercom.front_end_binding import InterComFrontEndBinding
from storage.redis_status_interface import RedisStatusInterface
from version import __VERSION__
from web_interface.app import create_app
from web_interface.components.ajax_routes import AjaxRoutes
from web_interface.components.analysis_routes import AnalysisRoutes
from web_interface.components.compare_routes import CompareRoutes
from web_interface.components.database_routes import DatabaseRoutes
from web_interface.components.io_routes import IORoutes
from web_interface.components.jinja_filter import FilterClass
from web_interface.components.miscellaneous_routes import MiscellaneousRoutes
from web_interface.components.plugin_routes import PluginRoutes
from web_interface.components.statistic_routes import StatisticRoutes
from web_interface.components.user_management_routes import UserManagementRoutes
from web_interface.frontend_database import FrontendDatabase
from web_interface.rest.rest_base import RestBase
from web_interface.security.authentication import add_flask_security_to_app


class WebFrontEnd:
    def __init__(self, db: FrontendDatabase | None = None, intercom=None, status_interface=None):
        self.program_version = __VERSION__
        self.intercom = InterComFrontEndBinding() if intercom is None else intercom
        self.db = FrontendDatabase() if db is None else db
        self.status_interface = RedisStatusInterface() if status_interface is None else status_interface

        self._setup_app()
        logging.info('Web front end online')

    def _setup_app(self):
        self.app = create_app()
        self.user_db, self.user_datastore = add_flask_security_to_app(self.app)
        base_args = {'app': self.app, 'db': self.db, 'intercom': self.intercom, 'status': self.status_interface}

        AjaxRoutes(**base_args)
        AnalysisRoutes(**base_args)
        CompareRoutes(**base_args)
        DatabaseRoutes(**base_args)
        IORoutes(**base_args)
        MiscellaneousRoutes(**base_args)
        StatisticRoutes(**base_args)
        UserManagementRoutes(**base_args, user_db=self.user_db, user_db_interface=self.user_datastore)

        rest_base = RestBase(**base_args)
        PluginRoutes(**base_args, api=rest_base.api)
        FilterClass(self.app, self.program_version, self.db)
