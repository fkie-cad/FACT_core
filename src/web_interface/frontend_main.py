import logging
import os

from flask import Flask

from version import __VERSION__
from web_interface.components.ajax_routes import AjaxRoutes
from web_interface.components.analysis_routes import AnalysisRoutes
from web_interface.components.compare_routes import CompareRoutes
from web_interface.components.database_routes import DatabaseRoutes
from web_interface.components.io_routes import IORoutes
from web_interface.components.jinja_filter import FilterClass
from web_interface.components.miscellaneous_routes import MiscellaneousRoutes
from web_interface.components.plugin_routes import PluginRoutes
from web_interface.components.user_management_routes import UserManagementRoutes
from web_interface.components.statistic_routes import StatisticRoutes
from web_interface.rest.rest_base import RestBase
from web_interface.security.authentication import add_flask_security_to_app


class WebFrontEnd(object):
    def __init__(self, config=None):
        self.config = config
        self.program_version = __VERSION__

        self._setup_app()
        logging.info("Web front end online")

    def _setup_app(self):
        self.app = Flask(__name__)
        self.app.config.from_object(__name__)

        Flask.secret_key = os.urandom(24)
        user_db, user_interface = add_flask_security_to_app(self.app, self.config)

        rest_base = RestBase(app=self.app, config=self.config)

        AjaxRoutes(self.app, self.config)
        AnalysisRoutes(self.app, self.config)
        CompareRoutes(self.app, self.config)
        DatabaseRoutes(self.app, self.config)
        IORoutes(self.app, self.config)
        MiscellaneousRoutes(self.app, self.config)
        PluginRoutes(self.app, self.config, api=rest_base.api)
        StatisticRoutes(self.app, self.config)
        UserManagementRoutes(self.app, self.config, user_db=user_db, user_db_interface=user_interface)

        FilterClass(self.app, self.program_version, self.config)
