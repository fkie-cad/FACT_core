import logging
from pathlib import Path
from typing import Optional

from storage.db_interface_view_sync import ViewUpdater


class BasePlugin:
    NAME = 'base'
    DEPENDENCIES = []

    def __init__(self, plugin_administrator, config=None, plugin_path=None, view_updater=None):
        self.plugin_administrator = plugin_administrator
        self.config = config
        self.view_updater = view_updater if view_updater is not None else ViewUpdater(config)
        if plugin_path:
            self._sync_view(plugin_path)

    def _sync_view(self, plugin_path: str):
        view_path = self._get_view_file_path(plugin_path)
        if view_path is not None:
            view_content = view_path.read_bytes()
            self.view_updater.update_view(self.NAME, view_content)

    @classmethod
    def _get_view_file_path(cls, plugin_path: str) -> Optional[Path]:
        views_dir = Path(plugin_path).parent.parent / 'view'
        view_files = list(views_dir.iterdir()) if views_dir.is_dir() else []
        if len(view_files) < 1:
            logging.debug(f'{cls.NAME}: No view available! Generic view will be used.')
            return None
        if len(view_files) > 1:
            logging.warning('{}: Plug-in provides more than one view! \'{}\' is used!'.format(cls.NAME, view_files[0]))
        return view_files[0]

    def register_plugin(self):
        self.plugin_administrator.register_plugin(self.NAME, self)
