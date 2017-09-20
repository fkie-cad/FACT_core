import logging

from flask import Flask

from helperFunctions.config import load_config
from web_interface.components.ajax_routes import AjaxRoutes
from web_interface.components.analysis_routes import AnalysisRoutes
from web_interface.components.compare_routes import CompareRoutes
from web_interface.components.database_routes import DatabaseRoutes
from web_interface.components.io_routes import IORoutes
from web_interface.components.jinja_filter import FilterClass
from web_interface.components.miscellaneous_routes import MiscellaneousRoutes
from web_interface.components.statistic_routes import StatisticRoutes
from web_interface.rest.rest_base import RestBase

CONFIG_FILE = "main.cfg"


class WebFrontEnd(object):
    def __init__(self,
                 config=None,
                 program_version="not_set",
                 ):
        self._setup_config(config)

        self.program_version = program_version

        self.setup_app()
        logging.info("Web front end online")

    def _setup_config(self, config):
        if config is None:
            self.config = load_config(CONFIG_FILE)
        else:
            self.config = config

    def setup_app(self):
        self.app = Flask(__name__)
        self.app.config.from_object(__name__)

        RestBase(app=self.app, config=self.config)

        AjaxRoutes(self.app, self.config)
        AnalysisRoutes(self.app, self.config)
        CompareRoutes(self.app, self.config)
        DatabaseRoutes(self.app, self.config)
        IORoutes(self.app, self.config)
        MiscellaneousRoutes(self.app, self.config)
        StatisticRoutes(self.app, self.config)

        FilterClass(self.app, self.program_version, self.config)
