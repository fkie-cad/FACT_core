from __future__ import annotations

from storage.db_connection import AdminConnection, ReadOnlyConnection, ReadWriteConnection, ReadWriteDeleteConnection
from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_comparison import ComparisonDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_frontend_editing import FrontendEditingDbInterface
from storage.db_interface_stats import StatsDbViewer, StatsUpdateDbInterface
from storage.db_interface_view_sync import ViewReader


class FrontendDatabase:  # pylint: disable=too-many-instance-attributes
    def __init__(  # pylint: disable=too-many-arguments
        self,
        frontend: type[FrontEndDbInterface] | None = None,
        editing: type[FrontendEditingDbInterface] | None = None,
        admin: type[AdminDbInterface] | None = None,
        comparison: type[ComparisonDbInterface] | None = None,
        template: type[ViewReader] | None = None,
        stats_viewer: type[StatsDbViewer] | None = None,
        stats_updater: type[StatsUpdateDbInterface] | None = None,
    ):
        self._ro_connection = ReadOnlyConnection()
        self._rw_connection = ReadWriteConnection()
        self._del_connection = ReadWriteDeleteConnection()
        self._admin_connection = AdminConnection()

        self._frontend = frontend if frontend is not None else FrontEndDbInterface
        self._editing = editing if editing is not None else FrontendEditingDbInterface
        self._admin = admin if admin is not None else AdminDbInterface
        self._comparison = comparison if comparison is not None else ComparisonDbInterface
        self._template = template if template is not None else ViewReader
        self._stats_viewer = stats_viewer if stats_viewer is not None else StatsDbViewer
        self._stats_updater = stats_updater if stats_updater is not None else StatsUpdateDbInterface

    @property
    def frontend(self) -> FrontEndDbInterface:
        return self._frontend(self._ro_connection)

    @property
    def editing(self) -> FrontendEditingDbInterface:
        return self._editing(self._rw_connection)

    @property
    def admin(self) -> AdminDbInterface:
        return self._admin(self._del_connection)

    @property
    def comparison(self) -> ComparisonDbInterface:
        return self._comparison(self._rw_connection)

    @property
    def template(self) -> ViewReader:
        return self._template(self._ro_connection)

    @property
    def stats_viewer(self) -> StatsDbViewer:
        return self._stats_viewer(self._ro_connection)

    @property
    def stats_updater(self) -> StatsUpdateDbInterface:
        return self._stats_updater(self._rw_connection)
