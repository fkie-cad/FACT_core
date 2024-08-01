from __future__ import annotations

import logging
from pathlib import Path

from fact.storage.db_interface_view_sync import ViewUpdater


class BasePlugin:
    NAME = 'base'
    DEPENDENCIES = []  # noqa: RUF012

    def __init__(self, plugin_path=None, view_updater=None):
        self.view_updater = view_updater if view_updater is not None else ViewUpdater()
        if plugin_path:
            self._sync_view(plugin_path)

    def _sync_view(self, plugin_path: str):
        view_path = self._get_view_file_path(plugin_path)
        if view_path is not None:
            view_content = view_path.read_bytes()
            self.view_updater.update_view(self.NAME, view_content)

    @classmethod
    def _get_view_file_path(cls, plugin_path: str) -> Path | None:
        views_dir = Path(plugin_path).parent.parent / 'view'
        view_files = list(views_dir.iterdir()) if views_dir.is_dir() else []
        if len(view_files) < 1:
            logging.debug(f'{cls.NAME}: No view available! Generic view will be used.')
            return None
        if len(view_files) > 1:
            logging.warning(f"{cls.NAME}: Plug-in provides more than one view! '{view_files[0]}' is used!")
        return view_files[0]
