from configparser import ConfigParser

from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_comparison import ComparisonDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_frontend_editing import FrontendEditingDbInterface
from storage.db_interface_stats import StatsDbViewer, StatsUpdateDbInterface
from storage.db_interface_view_sync import ViewReader


class FrontendDatabase:
    def __init__(
            self,
            config: ConfigParser,
    ):
        self.frontend = FrontEndDbInterface(config)
        self.editing = FrontendEditingDbInterface(config)
        self.admin = AdminDbInterface(config)
        self.comparison = ComparisonDbInterface(config)
        self.template = ViewReader(config)
        self.stats_viewer = StatsDbViewer(config)
        self.stats_updater = StatsUpdateDbInterface(config)
