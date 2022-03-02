from configparser import ConfigParser
from typing import Optional

from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_comparison import ComparisonDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_frontend_editing import FrontendEditingDbInterface
from storage.db_interface_stats import StatsDbViewer, StatsUpdateDbInterface
from storage.db_interface_view_sync import ViewReader


class FrontendDatabase:
    def __init__(  # pylint: disable=too-many-arguments
            self,
            config: ConfigParser,
            frontend: Optional[FrontEndDbInterface] = None,
            editing: Optional[FrontendEditingDbInterface] = None,
            admin: Optional[AdminDbInterface] = None,
            comparison: Optional[ComparisonDbInterface] = None,
            template: Optional[ViewReader] = None,
            stats_viewer: Optional[StatsDbViewer] = None,
            stats_updater: Optional[StatsUpdateDbInterface] = None
    ):
        self.frontend = frontend if frontend is not None else FrontEndDbInterface(config)
        self.editing = editing if frontend is not None else FrontendEditingDbInterface(config)
        self.admin = admin if frontend is not None else AdminDbInterface(config)
        self.comparison = comparison if frontend is not None else ComparisonDbInterface(config)
        self.template = template if frontend is not None else ViewReader(config)
        self.stats_viewer = stats_viewer if frontend is not None else StatsDbViewer(config)
        self.stats_updater = stats_updater if frontend is not None else StatsUpdateDbInterface(config)
